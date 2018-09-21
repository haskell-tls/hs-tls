{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}

-- |
-- Module      : Network.TLS.Record.Disengage13
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Disengage a record from the Record layer.
-- The record is decrypted, checked for integrity and then decompressed.
--
module Network.TLS.Record.Disengage13
        ( disengageRecord13
        ) where

import Control.Monad.State

import Network.TLS.Imports
import Crypto.Cipher.Types (AuthTag(..))
import Network.TLS.Struct
import Network.TLS.ErrT
import Network.TLS.Record.State
import Network.TLS.Record.Types
import Network.TLS.Cipher
import Network.TLS.Util
import Network.TLS.Wire
import qualified Data.ByteString as B
import qualified Data.ByteArray as B (convert, xor)

disengageRecord13 :: Record Ciphertext -> RecordM (Record Plaintext)
disengageRecord13 = decryptRecord >=> uncompressRecord

uncompressRecord :: Record Compressed -> RecordM (Record Plaintext)
uncompressRecord record = onRecordFragment record $ fragmentUncompress return

decryptRecord :: Record Ciphertext -> RecordM (Record Compressed)
decryptRecord record@(Record ct ver fragment) =
    case ct of
        ProtocolType_AppData -> do
            st <- get
            case stCipher st of
                Nothing -> noDecryption
                _       -> do
                    inner <- decryptData (fragmentGetBytes fragment) st
                    let (dc,_pad) = B.spanEnd (== 0) inner
                        Just (d,c) = B.unsnoc dc
                        Just ct' = valToType c
                    return $ Record ct' ver (fragmentCompressed d)
        _ -> noDecryption
  where noDecryption = onRecordFragment record $ fragmentUncipher return

decryptData :: ByteString -> RecordState -> RecordM ByteString
decryptData econtent tst = decryptOf (cstKey cst)
  where cipher     = fromJust "cipher" $ stCipher tst
        bulk       = cipherBulk cipher
        cst        = stCryptState tst
        econtentLen = B.length econtent

        decryptOf :: BulkState -> RecordM ByteString
        decryptOf (BulkStateAEAD decryptF) = do
            let authTagLen  = bulkAuthTagLen bulk
                cipherLen   = econtentLen - authTagLen

            (econtent', authTag) <- get2o econtent (cipherLen, authTagLen)
            let encodedSeq = encodeWord64 $ msSequence $ stMacState tst
                iv = cstIV cst
                ivlen = B.length iv
                sqnc = B.replicate (ivlen - 8) 0 `B.append` encodedSeq
                nonce = B.xor iv sqnc
                additional = "\23\3\3" `B.append` encodeWord16 (fromIntegral econtentLen)
                (content, authTag2) = decryptF nonce econtent' additional

            when (AuthTag (B.convert authTag) /= authTag2) $
                throwError $ Error_Protocol ("bad record mac", True, BadRecordMac)
            modify incrRecordState
            return content

        decryptOf _ =
            throwError $ Error_Protocol ("decrypt state uninitialized", True, InternalError)

        -- handling of outer format can report errors with Error_Packet
        get3o s ls = maybe (throwError $ Error_Packet "record bad format 1.3") return $ partition3 s ls
        get2o s (d1,d2) = get3o s (d1,d2,0) >>= \(r1,r2,_) -> return (r1,r2)
