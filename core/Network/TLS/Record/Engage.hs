-- |
-- Module      : Network.TLS.Record.Engage
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Engage a record into the Record layer.
-- The record is compressed, added some integrity field, then encrypted.
--
-- Starting with TLS v1.3, only the "null" compression method is negotiated in
-- the handshake, so the compression step will be a no-op.  Integrity and
-- encryption are performed using an AEAD cipher only.
--
{-# LANGUAGE BangPatterns #-}
module Network.TLS.Record.Engage
        ( engageRecord
        ) where

import Control.Monad.State.Strict
import Crypto.Cipher.Types (AuthTag(..))

import Network.TLS.Cap
import Network.TLS.Record.State
import Network.TLS.Record.Types
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Wire
import Network.TLS.Packet
import Network.TLS.Struct
import Network.TLS.Imports
import qualified Data.ByteString as B
import qualified Data.ByteArray as B (convert, xor)

engageRecord :: Record Plaintext -> RecordM (Record Ciphertext)
engageRecord = compressRecord >=> encryptRecord

compressRecord :: Record Plaintext -> RecordM (Record Compressed)
compressRecord record =
    onRecordFragment record $ fragmentCompress $ \bytes -> do
        withCompression $ compressionDeflate bytes

-- when Tx Encrypted is set, we pass the data through encryptContent, otherwise
-- we just return the compress payload directly as the ciphered one
--
encryptRecord :: Record Compressed -> RecordM (Record Ciphertext)
encryptRecord record@(Record ct ver fragment) = do
    st <- get
    case stCipher st of
        Nothing -> noEncryption
        _ -> do
            recOpts <- getRecordOptions
            if recordTLS13 recOpts
                then encryptContent13
                else onRecordFragment record $ fragmentCipher (encryptContent False record)
  where
    noEncryption = onRecordFragment record $ fragmentCipher return
    encryptContent13
        | ct == ProtocolType_ChangeCipherSpec = noEncryption
        | otherwise = do
            let bytes     = fragmentGetBytes fragment
                fragment' = fragmentCompressed $ innerPlaintext ct bytes
                record'   = Record ProtocolType_AppData ver fragment'
            onRecordFragment record' $ fragmentCipher (encryptContent True record')

innerPlaintext :: ProtocolType -> ByteString -> ByteString
innerPlaintext ct bytes = runPut $ do
    putBytes bytes
    putWord8 $ valOfType ct -- non zero!
    -- fixme: zeros padding

encryptContent :: Bool -> Record Compressed -> ByteString -> RecordM ByteString
encryptContent tls13 record content = do
    cst  <- getCryptState
    bulk <- getBulk
    case cstKey cst of
        BulkStateBlock encryptF -> do
            digest <- makeDigest (recordToHeader record) content
            let content' =  B.concat [content, digest]
            encryptBlock encryptF content' bulk
        BulkStateStream encryptF -> do
            digest <- makeDigest (recordToHeader record) content
            let content' =  B.concat [content, digest]
            encryptStream encryptF content'
        BulkStateAEAD encryptF ->
            encryptAead tls13 bulk encryptF content record
        BulkStateUninitialized ->
            return content

encryptBlock :: BulkBlock -> ByteString -> Bulk -> RecordM ByteString
encryptBlock encryptF content bulk = do
    cst <- getCryptState
    ver <- getRecordVersion
    let blockSize = fromIntegral $ bulkBlockSize bulk
    let msg_len = B.length content
    let padding = if blockSize > 0
                  then
                      let padbyte = blockSize - (msg_len `mod` blockSize) in
                      let padbyte' = if padbyte == 0 then blockSize else padbyte in B.replicate padbyte' (fromIntegral (padbyte' - 1))
                  else
                      B.empty

    let (e, iv') = encryptF (cstIV cst) $ B.concat [ content, padding ]

    if hasExplicitBlockIV ver
        then return $ B.concat [cstIV cst,e]
        else do
            modify $ \tstate -> tstate { stCryptState = cst { cstIV = iv' } }
            return e

encryptStream :: BulkStream -> ByteString -> RecordM ByteString
encryptStream (BulkStream encryptF) content = do
    cst <- getCryptState
    let (!e, !newBulkStream) = encryptF content
    modify $ \tstate -> tstate { stCryptState = cst { cstKey = BulkStateStream newBulkStream } }
    return e

encryptAead :: Bool
            -> Bulk
            -> BulkAEAD
            -> ByteString -> Record Compressed
            -> RecordM ByteString
encryptAead tls13 bulk encryptF content record = do
    let authTagLen  = bulkAuthTagLen bulk
        nonceExpLen = bulkExplicitIV bulk
    cst        <- getCryptState
    encodedSeq <- encodeWord64 <$> getMacSequence

    let iv    = cstIV cst
        ivlen = B.length iv
        Header typ v plainLen = recordToHeader record
        hdrLen = if tls13 then plainLen + fromIntegral authTagLen else plainLen
        hdr = Header typ v hdrLen
        ad | tls13     = encodeHeader hdr
           | otherwise = B.concat [ encodedSeq, encodeHeader hdr ]
        sqnc  = B.replicate (ivlen - 8) 0 `B.append` encodedSeq
        nonce | nonceExpLen == 0 = B.xor iv sqnc
              | otherwise = B.concat [iv, encodedSeq]
        (e, AuthTag authtag) = encryptF nonce content ad
        econtent | nonceExpLen == 0 = e `B.append` B.convert authtag
                 | otherwise = B.concat [encodedSeq, e, B.convert authtag]
    modify incrRecordState
    return econtent

getCryptState :: RecordM CryptState
getCryptState = stCryptState <$> get
