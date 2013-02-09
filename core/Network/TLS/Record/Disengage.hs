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
                then get >>= decryptData record e
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
                throwError $ Error_Protocol ("bad record mac", True, BadRecordMac)

        return $ cipherDataContent cdata

decryptData :: Record Ciphertext -> Bytes -> TLSState -> TLSSt Bytes
decryptData record econtent st = decryptOf (bulkF bulk)
    where cipher     = fromJust "cipher" $ stActiveRxCipher st
          bulk       = cipherBulk cipher
          cst        = fromJust "rx crypt state" $ stActiveRxCryptState st
          macSize    = hashSize $ cipherHash cipher
          writekey   = cstKey cst
          blockSize  = bulkBlockSize bulk
          econtentLen = B.length econtent

          explicitIV = hasExplicitBlockIV $ stVersion st

          sanityCheckError = throwError (Error_Packet "encrypted content too small for encryption parameters")

          decryptOf :: BulkFunctions -> TLSSt Bytes
          decryptOf (BulkBlockF _ decryptF) = do
            let minContent = (if explicitIV then bulkIVSize bulk else 0) + max (macSize + 1) blockSize
            when ((econtentLen `mod` blockSize) /= 0 || econtentLen < minContent) $ sanityCheckError
            {- update IV -}
            (iv, econtent') <- if explicitIV
                                  then get2 econtent (bulkIVSize bulk, econtentLen - bulkIVSize bulk)
                                  else return (cstIV cst, econtent)
            let newiv = fromJust "new iv" $ takelast (bulkBlockSize bulk) econtent'
            put $ st { stActiveRxCryptState = Just $ cst { cstIV = newiv } }

            let content' = decryptF writekey iv econtent'
            let paddinglength = fromIntegral (B.last content') + 1
            let contentlen = B.length content' - paddinglength - macSize
            (content, mac, padding) <- get3 content' (contentlen, macSize, paddinglength)
            getCipherData record $ CipherData
                    { cipherDataContent = content
                    , cipherDataMAC     = Just mac
                    , cipherDataPadding = Just padding
                    }

          decryptOf (BulkStreamF initF _ decryptF) = do
            when (econtentLen < macSize) $ sanityCheckError
            let iv = cstIV cst
            let (content', newiv) = decryptF (if iv /= B.empty then iv else initF writekey) econtent
            {- update Ctx -}
            let contentlen        = B.length content' - macSize
            (content, mac) <- get2 content' (contentlen, macSize)
            put $ st { stActiveRxCryptState = Just $ cst { cstIV = newiv } }
            getCipherData record $ CipherData
                    { cipherDataContent = content
                    , cipherDataMAC     = Just mac
                    , cipherDataPadding = Nothing
                    }

          get3 s ls = maybe (throwError $ Error_Packet "record bad format") return $ partition3 s ls
          get2 s (d1,d2) = get3 s (d1,d2,0) >>= \(r1,r2,_) -> return (r1,r2)
