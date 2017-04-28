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
{-# LANGUAGE FlexibleContexts #-}

module Network.TLS.Record.Disengage
        ( disengageRecord
        ) where

import Control.Monad.State.Strict

import Crypto.Cipher.Types (AuthTag(..))
import Network.TLS.Struct
import Network.TLS.ErrT
import Network.TLS.Cap
import Network.TLS.Record.State
import Network.TLS.Record.Types
import Network.TLS.Cipher
import Network.TLS.Crypto
import Network.TLS.Compression
import Network.TLS.Util
import Network.TLS.Wire
import Network.TLS.Packet
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteArray as B (convert)

disengageRecord :: Record Ciphertext -> RecordM (Record Plaintext)
disengageRecord = decryptRecord >=> uncompressRecord

uncompressRecord :: Record Compressed -> RecordM (Record Plaintext)
uncompressRecord record = onRecordFragment record $ fragmentUncompress $ \bytes ->
    withCompression $ compressionInflate bytes

decryptRecord :: Record Ciphertext -> RecordM (Record Compressed)
decryptRecord record = onRecordFragment record $ fragmentUncipher $ \e -> do
    st <- get
    case stCipher st of
        Nothing -> return e
        _       -> getRecordVersion >>= \ver -> decryptData ver record e st

getCipherData :: Record a -> CipherData -> RecordM ByteString
getCipherData (Record pt ver _) cdata = do
    -- check if the MAC is valid.
    macValid <- case cipherDataMAC cdata of
        Nothing     -> return True
        Just digest -> do
            let new_hdr = Header pt ver (fromIntegral $ B.length $ cipherDataContent cdata)
            expected_digest <- makeDigest new_hdr $ cipherDataContent cdata
            return (expected_digest `bytesEq` digest)

    -- check if the padding is filled with the correct pattern if it exists
    paddingValid <- case cipherDataPadding cdata of
        Nothing  -> return True
        Just pad -> do
            cver <- getRecordVersion
            let b = B.length pad - 1
            return (if cver < TLS10 then True else B.replicate (B.length pad) (fromIntegral b) `bytesEq` pad)

    unless (macValid &&! paddingValid) $ do
        throwError $ Error_Protocol ("bad record mac", True, BadRecordMac)

    return $ cipherDataContent cdata

decryptData :: Version -> Record Ciphertext -> Bytes -> RecordState -> RecordM Bytes
decryptData ver record econtent tst = decryptOf (cstKey cst)
  where cipher     = fromJust "cipher" $ stCipher tst
        bulk       = cipherBulk cipher
        cst        = stCryptState tst
        macSize    = hashDigestSize $ cipherHash cipher
        blockSize  = bulkBlockSize bulk
        econtentLen = B.length econtent

        explicitIV = hasExplicitBlockIV ver

        sanityCheckError = throwError (Error_Packet "encrypted content too small for encryption parameters")

        decryptOf :: BulkState -> RecordM Bytes
        decryptOf (BulkStateBlock decryptF) = do
            let minContent = (if explicitIV then bulkIVSize bulk else 0) + max (macSize + 1) blockSize

            -- check if we have enough bytes to cover the minimum for this cipher
            when ((econtentLen `mod` blockSize) /= 0 || econtentLen < minContent) $ sanityCheckError

            {- update IV -}
            (iv, econtent') <- if explicitIV
                                  then get2 econtent (bulkIVSize bulk, econtentLen - bulkIVSize bulk)
                                  else return (cstIV cst, econtent)
            let (content', iv') = decryptF iv econtent'
            modify $ \txs -> txs { stCryptState = cst { cstIV = iv' } }

            let paddinglength = fromIntegral (B.last content') + 1
            let contentlen = B.length content' - paddinglength - macSize
            (content, mac, padding) <- get3 content' (contentlen, macSize, paddinglength)
            getCipherData record $ CipherData
                    { cipherDataContent = content
                    , cipherDataMAC     = Just mac
                    , cipherDataPadding = Just padding
                    }

        decryptOf (BulkStateStream (BulkStream decryptF)) = do
            -- check if we have enough bytes to cover the minimum for this cipher
            when (econtentLen < macSize) $ sanityCheckError

            let (content', bulkStream') = decryptF econtent
            {- update Ctx -}
            let contentlen        = B.length content' - macSize
            (content, mac) <- get2 content' (contentlen, macSize)
            modify $ \txs -> txs { stCryptState = cst { cstKey = BulkStateStream bulkStream' } }
            getCipherData record $ CipherData
                    { cipherDataContent = content
                    , cipherDataMAC     = Just mac
                    , cipherDataPadding = Nothing
                    }

        decryptOf (BulkStateAEAD decryptF) = do
            let authTagLen  = bulkAuthTagLen bulk
                nonceExpLen = bulkExplicitIV bulk
                cipherLen   = econtentLen - authTagLen - nonceExpLen

            -- check if we have enough bytes to cover the minimum for this cipher
            when (econtentLen < (authTagLen + nonceExpLen)) $ sanityCheckError

            (enonce, econtent', authTag) <- get3 econtent (nonceExpLen, cipherLen, authTagLen)
            let encodedSeq = encodeWord64 $ msSequence $ stMacState tst
                Header typ v _ = recordToHeader record
                hdr = Header typ v $ fromIntegral cipherLen
                ad = B.concat [ encodedSeq, encodeHeader hdr ]
                nonce = cstIV (stCryptState tst) `B.append` enonce
                (content, authTag2) = decryptF nonce econtent' ad

            when (AuthTag (B.convert authTag) /= authTag2) $
                throwError $ Error_Protocol ("bad record mac", True, BadRecordMac)

            modify incrRecordState
            return content

        decryptOf BulkStateUninitialized =
            throwError $ Error_Protocol ("decrypt state uninitialized", True, InternalError)

        get3 s ls = maybe (throwError $ Error_Packet "record bad format") return $ partition3 s ls
        get2 s (d1,d2) = get3 s (d1,d2,0) >>= \(r1,r2,_) -> return (r1,r2)
