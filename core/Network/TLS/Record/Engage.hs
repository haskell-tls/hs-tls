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
import Network.TLS.Util
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
    bulk <- getBulk
    case bulkF bulk of
        BulkBlockF encryptF _ -> do
            digest <- makeDigest (recordToHeader record) content
            let content' =  B.concat [content, digest]
            encryptBlock encryptF content' bulk
        BulkStreamF initF encryptF _ -> do
            digest <- makeDigest (recordToHeader record) content
            let content' =  B.concat [content, digest]
            encryptStream encryptF content' initF
        BulkAeadF encryptF _ ->
            encryptAead encryptF content record

encryptBlock :: (Key -> IV -> ByteString -> ByteString)
             -> ByteString -> Bulk
             -> RecordM ByteString
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

    let e = encryptF (cstKey cst) (cstIV cst) $ B.concat [ content, padding ]

    if hasExplicitBlockIV ver
        then return $ B.concat [cstIV cst,e]
        else do
            let newiv = fromJust "new iv" $ takelast (bulkIVSize bulk) e
            modify $ \tstate -> tstate { stCryptState = cst { cstIV = newiv } }
            return e

encryptStream :: (IV -> ByteString -> (ByteString, IV))
              -> ByteString -> (Key -> IV)
              -> RecordM ByteString
encryptStream encryptF content initF = do
    cst <- getCryptState
    let iv = cstIV cst
        (e, newiv) = encryptF (if iv /= B.empty then iv else initF (cstKey cst)) content
    modify $ \tstate -> tstate { stCryptState = cst { cstIV = newiv } }
    return e

encryptAead :: (Key -> Nonce -> ByteString -> AdditionalData -> (ByteString, AuthTag))
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
    let (e, AuthTag authtag) = encryptF (cstKey cst) nonce content ad
    modify incrRecordState
    return $ B.concat [processorNum, counter, e, authtag]

getCryptState :: RecordM CryptState
getCryptState = stCryptState <$> get
