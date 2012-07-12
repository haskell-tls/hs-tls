-- |
-- Module      : Network.TLS.Record.Disengage
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Disengage a record from the Record layer.
-- The record is decrypted, checked for integrity and then decompressed.
--
module Network.TLS.Record.Disengage
        ( disengageRecord
        ) where

import Control.Monad.State
import Control.Monad.Error

import Network.TLS.Struct
import Network.TLS.Cap
import Network.TLS.State
import Network.TLS.Record.Types
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Util
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

disengageRecord :: Record Ciphertext -> TLSSt (Record Plaintext)
disengageRecord = decryptRecord >=> uncompressRecord

uncompressRecord :: Record Compressed -> TLSSt (Record Plaintext)
uncompressRecord record = onRecordFragment record $ fragmentUncompress $ \bytes ->
        withCompression $ compressionInflate bytes

decryptRecord :: Record Ciphertext -> TLSSt (Record Compressed)
decryptRecord record = onRecordFragment record $ fragmentUncipher $ \e -> do
        st <- get
        if stRxEncrypted st
                then decryptData e >>= getCipherData record
                else return e

getCipherData :: Record a -> CipherData -> TLSSt ByteString
getCipherData (Record pt ver _) cdata = do
        -- check if the MAC is valid.
        macValid <- case cipherDataMAC cdata of
                Nothing     -> return True
                Just digest -> do
                        let new_hdr = Header pt ver (fromIntegral $ B.length $ cipherDataContent cdata)
                        expected_digest <- makeDigest False new_hdr $ cipherDataContent cdata
                        return (expected_digest `bytesEq` digest)

        -- check if the padding is filled with the correct pattern if it exists
        paddingValid <- case cipherDataPadding cdata of
                Nothing  -> return True
                Just pad -> do
                        cver <- gets stVersion
                        let b = B.length pad - 1
                        return (if cver < TLS10 then True else B.replicate (B.length pad) (fromIntegral b) `bytesEq` pad)

        unless (macValid &&! paddingValid) $ do
                throwError $ Error_Protocol (("bad record mac: " ++
                                             (if not macValid then "!macValid" else "") ++
                                             " " ++
                                             (if not paddingValid then "!paddingValid" else "")
                                                ), True, BadRecordMac)

        return $ cipherDataContent cdata

decryptData :: Bytes -> TLSSt CipherData
decryptData econtent = do
        st <- get

        let cipher     = fromJust "cipher" $ stCipher st
        let bulk       = cipherBulk cipher
        let cst        = fromJust "rx crypt state" $ stRxCryptState st
        let digestSize = hashSize $ cipherHash cipher
        let writekey   = cstKey cst

        case bulkF bulk of
                BulkNoneF -> do
                        let contentlen = B.length econtent - digestSize
                        case partition3 econtent (contentlen, digestSize, 0) of
                                Nothing                ->
                                        throwError $ Error_Misc "partition3 failed"
                                Just (content, mac, _) ->
                                        return $ CipherData
                                                { cipherDataContent = content
                                                , cipherDataMAC     = Just mac
                                                , cipherDataPadding = Nothing
                                                }
                BulkBlockF _ decryptF -> do
                        {- update IV -}
                        let (iv, econtent') =
                                if hasExplicitBlockIV $ stVersion st
                                        then B.splitAt (bulkIVSize bulk) econtent
                                        else (cstIV cst, econtent)
                        let newiv = fromJust "new iv" $ takelast (bulkBlockSize bulk) econtent'
                        put $ st { stRxCryptState = Just $ cst { cstIV = newiv } }

                        let content' = decryptF writekey iv econtent'
                        let paddinglength = fromIntegral (B.last content') + 1
                        let contentlen = B.length content' - paddinglength - digestSize
                        let (content, mac, padding) = fromJust "p3" $ partition3 content' (contentlen, digestSize, paddinglength)
                        return $ CipherData
                                { cipherDataContent = content
                                , cipherDataMAC     = Just mac
                                , cipherDataPadding = Just padding
                                }
                BulkStreamF initF _ decryptF -> do
                        let iv = cstIV cst
                        let (content', newiv) = decryptF (if iv /= B.empty then iv else initF writekey) econtent
                        {- update Ctx -}
                        let contentlen        = B.length content' - digestSize
                        let (content, mac, _) = fromJust "p3" $ partition3 content' (contentlen, digestSize, 0)
                        put $ st { stRxCryptState = Just $ cst { cstIV = newiv } }
                        return $ CipherData
                                { cipherDataContent = content
                                , cipherDataMAC     = Just mac
                                , cipherDataPadding = Nothing
                                }

