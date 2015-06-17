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
{-# LANGUAGE BangPatterns #-}
module Network.TLS.Record.Engage
        ( engageRecord
        ) where

import Control.Applicative
import Control.Monad.State
import Crypto.Cipher.Types (AuthTag(..))

import Network.TLS.Cap
import Network.TLS.Record.State
import Network.TLS.Record.Types
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Wire
import Network.TLS.Packet
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

engageRecord :: Record Plaintext -> RecordM (Record Ciphertext)
engageRecord = compressRecord >=> encryptRecord

compressRecord :: Record Plaintext -> RecordM (Record Compressed)
compressRecord record =
    onRecordFragment record $ fragmentCompress $ \bytes -> do
        withCompression $ compressionDeflate bytes

{-
 - when Tx Encrypted is set, we pass the data through encryptContent, otherwise
 - we just return the packet
 -}
encryptRecord :: Record Compressed -> RecordM (Record Ciphertext)
encryptRecord record = onRecordFragment record $ fragmentCipher $ \bytes -> do
    st <- get
    case stCipher st of
        Nothing -> return bytes
        _       -> encryptContent record bytes

encryptContent :: Record Compressed -> ByteString -> RecordM ByteString
encryptContent record content = do
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
            encryptAead encryptF content record
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

encryptAead :: BulkAEAD
            -> ByteString -> Record Compressed
            -> RecordM ByteString
encryptAead encryptF content record = do
    cst        <- getCryptState
    encodedSeq <- encodeWord64 <$> getMacSequence

    let hdr = recordToHeader record
        ad = B.concat [ encodedSeq, encodeHeader hdr ]
    let salt = cstIV cst
        processorNum = encodeWord32 1 -- FIXME
        counter = B.drop 4 encodedSeq -- FIXME: probably OK
        nonce = B.concat [salt, processorNum, counter]
    let (e, AuthTag authtag) = encryptF nonce content ad
    modify incrRecordState
    return $ B.concat [processorNum, counter, e, authtag]

getCryptState :: RecordM CryptState
getCryptState = stCryptState <$> get
