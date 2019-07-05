{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Network.TLS.Record.Engage13
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Engage a record into the Record layer.
-- The record is compressed, added some integrity field, then encrypted.
--
module Network.TLS.Record.Engage13
        ( engageRecord
        ) where

import Control.Monad.State
import Crypto.Cipher.Types (AuthTag(..))

import Network.TLS.Record.State
import Network.TLS.Record.Types13
import Network.TLS.Cipher
import Network.TLS.Wire
import Network.TLS.Struct (ProtocolType(..), valOfType)
import Network.TLS.Imports
import Network.TLS.Util
import qualified Data.ByteString as B
import qualified Data.ByteArray as B (convert, xor)

engageRecord :: Record13 -> RecordM Record13
engageRecord record@(Record13 ProtocolType_ChangeCipherSpec _ _) = return record
engageRecord record@(Record13 ct ver bytes) = do
    st <- get
    case stCipher st of
        Nothing -> return record
        _       -> do
            ebytes <- encryptContent $ innerPlaintext ct bytes
            return $ Record13 ProtocolType_AppData ver ebytes

innerPlaintext :: ProtocolType -> ByteString -> ByteString
innerPlaintext ct bytes = runPut $ do
    putBytes bytes
    putWord8 $ valOfType ct -- non zero!
    -- fixme: zeros padding

encryptContent :: ByteString -> RecordM ByteString
encryptContent content = do
    st <- get
    let cst = stCryptState st
    case cstKey cst of
        BulkStateBlock _  -> error "encryptContent"
        BulkStateStream _ -> error "encryptContent"
        BulkStateUninitialized -> return content
        BulkStateAEAD encryptF -> do
            encodedSeq <- encodeWord64 <$> getMacSequence
            let iv = cstIV cst
                ivlen = B.length iv
                sqnc = B.replicate (ivlen - 8) 0 `B.append` encodedSeq
                nonce = B.xor iv sqnc
                bulk = cipherBulk $ fromJust "cipher" $ stCipher st
                authTagLen = bulkAuthTagLen bulk
                plainLen = B.length content
                econtentLen = plainLen + authTagLen
                additional = "\23\3\3" `B.append` encodeWord16 (fromIntegral econtentLen)
                (e, AuthTag authtag) = encryptF nonce content additional
                econtent = e `B.append` B.convert authtag
            modify incrRecordState
            return econtent
