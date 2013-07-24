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

import Network.TLS.Cap
import Network.TLS.Record.State
import Network.TLS.Record.Types
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Util
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

engageRecord :: Record Plaintext -> RecordM (Record Ciphertext)
engageRecord = compressRecord >=> encryptRecord

compressRecord :: Record Plaintext -> RecordM (Record Compressed)
compressRecord record =
    onRecordFragment record $ fragmentCompress $ \bytes -> do
        withTxCompression $ compressionDeflate bytes

{-
 - when Tx Encrypted is set, we pass the data through encryptContent, otherwise
 - we just return the packet
 -}
encryptRecord :: Record Compressed -> RecordM (Record Ciphertext)
encryptRecord record = onRecordFragment record $ fragmentCipher $ \bytes -> do
    st <- get
    case stCipher $ stTxState st of
        Nothing -> return bytes
        _       -> encryptContent record bytes

encryptContent :: Record Compressed -> ByteString -> RecordM ByteString
encryptContent record content = do
    digest <- makeDigest True (recordToHeader record) content
    encryptData $ B.concat [content, digest]

encryptData :: ByteString -> RecordM ByteString
encryptData content = do
    st <- get

    let tstate = stTxState st
    let cipher = fromJust "cipher" $ stCipher tstate
    let bulk = cipherBulk cipher
    let cst = stCryptState tstate

    let writekey = cstKey cst

    case bulkF bulk of
        BulkBlockF encrypt _ -> do
            let blockSize = fromIntegral $ bulkBlockSize bulk
            let msg_len = B.length content
            let padding = if blockSize > 0
                    then
                            let padbyte = blockSize - (msg_len `mod` blockSize) in
                            let padbyte' = if padbyte == 0 then blockSize else padbyte in
                            B.replicate padbyte' (fromIntegral (padbyte' - 1))
                    else
                            B.empty

            let e = encrypt writekey (cstIV cst) (B.concat [ content, padding ])
            if hasExplicitBlockIV $ stVersion st
                    then return $ B.concat [cstIV cst,e]
                    else do
                            let newiv = fromJust "new iv" $ takelast (bulkIVSize bulk) e
                            modifyTxState_ $ \txs -> txs { stCryptState = cst { cstIV = newiv } }
                            return e
        BulkStreamF initF encryptF _ -> do
            let iv = cstIV cst
            let (e, newiv) = encryptF (if iv /= B.empty then iv else initF writekey) content
            modifyTxState_ $ \txs -> txs { stCryptState = cst { cstIV = newiv } }
            return e
