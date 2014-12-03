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
    tstate <- get

    let cipher = fromJust "cipher" $ stCipher tstate
    let bulk = cipherBulk cipher
    let cst = stCryptState tstate

    let writekey = cstKey cst

    case bulkF bulk of
        BulkBlockF encryptF _ -> do
            digest <- makeDigest (recordToHeader record) content
            let content' =  B.concat [content, digest]
            encryptBlock encryptF writekey content' cst tstate bulk
        BulkStreamF initF encryptF _ -> do
            digest <- makeDigest (recordToHeader record) content
            let content' =  B.concat [content, digest]
            encryptStream encryptF writekey content' cst tstate initF
        BulkAeadF encryptF _ ->
            encryptAead encryptF writekey content cst tstate record

encryptBlock :: (Key -> IV -> ByteString -> ByteString)
             -> Key -> ByteString -> CryptState -> RecordState -> Bulk
             -> RecordM ByteString
encryptBlock encryptF writekey content cst tstate bulk = do
    ver <- getRecordVersion
    let blockSize = fromIntegral $ bulkBlockSize bulk
    let msg_len = B.length content
    let padding = if blockSize > 0
                  then
                      let padbyte = blockSize - (msg_len `mod` blockSize) in
                      let padbyte' = if padbyte == 0 then blockSize else padbyte in                   B.replicate padbyte' (fromIntegral (padbyte' - 1))
                  else
                      B.empty

    let iv = cstIV cst
        e = encryptF writekey iv $ B.concat [ content, padding ]
    if hasExplicitBlockIV ver
        then return $ B.concat [iv,e]
        else do
            let newiv = fromJust "new iv" $ takelast (bulkIVSize bulk) e
            put $ tstate { stCryptState = cst { cstIV = newiv } }
            return e

encryptStream :: (IV -> ByteString -> (ByteString, IV))
              -> Key -> ByteString -> CryptState -> RecordState -> (Key -> IV)
              -> RecordM ByteString
encryptStream encryptF writekey content cst tstate initF = do
    let iv = cstIV cst
    let (e, newiv) = encryptF (if iv /= B.empty then iv else initF writekey) content
    put $ tstate { stCryptState = cst { cstIV = newiv } }
    return e

encryptAead :: (Key -> Nonce -> ByteString -> AdditionalData -> (ByteString, AuthTag))
            -> Key -> ByteString -> CryptState -> RecordState -> Record Compressed
            -> RecordM ByteString
encryptAead encryptF writekey content cst tstate record = do
    let encodedSeq = encodeWord64 $ msSequence $ stMacState tstate
        hdr = recordToHeader record
        ad = B.concat [ encodedSeq, encodeHeader hdr ]
    let salt = cstIV cst
        processorNum = encodeWord32 1 -- FIXME
        counter = B.drop 4 encodedSeq -- FIXME: probably OK
        nonce = B.concat [salt, processorNum, counter]
    let (e, AuthTag authtag) = encryptF writekey nonce content ad
    modify incrRecordState
    return $ B.concat [processorNum, counter, e, authtag]
