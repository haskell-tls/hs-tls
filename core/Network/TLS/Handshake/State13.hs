{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Network.TLS.Handshake.State13
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.State13
       ( getTxState
       , getRxState
       , setTxState
       , setRxState
       , setHelloParameters13
       , transcriptHash
       , setPendingActions
       , popPendingAction
       ) where

import Control.Concurrent.MVar
import Control.Monad.State
import qualified Data.ByteString as B
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Handshake.State
import Network.TLS.KeySchedule (hkdfExpandLabel)
import Network.TLS.Record.State
import Network.TLS.Imports
import Network.TLS.Util

getTxState :: Context -> IO (Hash, Cipher, ByteString)
getTxState ctx = getXState ctx ctxTxState

getRxState :: Context -> IO (Hash, Cipher, ByteString)
getRxState ctx = getXState ctx ctxRxState

getXState :: Context
          -> (Context -> MVar RecordState)
          -> IO (Hash, Cipher, ByteString)
getXState ctx func = do
    tx <- readMVar (func ctx)
    let Just usedCipher = stCipher tx
        usedHash = cipherHash usedCipher
        secret = cstMacSecret $ stCryptState tx
    return (usedHash, usedCipher, secret)

setTxState :: Context -> Hash -> Cipher -> ByteString -> IO ()
setTxState = setXState ctxTxState BulkEncrypt

setRxState :: Context -> Hash -> Cipher -> ByteString -> IO ()
setRxState = setXState ctxRxState BulkDecrypt

setXState :: (Context -> MVar RecordState) -> BulkDirection
          -> Context -> Hash -> Cipher -> ByteString
          -> IO ()
setXState func encOrDec ctx h cipher secret =
    modifyMVar_ (func ctx) (\_ -> return rt)
  where
    bulk    = cipherBulk cipher
    keySize = bulkKeySize bulk
    ivSize  = max 8 (bulkIVSize bulk + bulkExplicitIV bulk)
    key = hkdfExpandLabel h secret "key" "" keySize
    iv  = hkdfExpandLabel h secret "iv"  "" ivSize
    cst = CryptState {
        cstKey       = bulkInit bulk encOrDec key
      , cstIV        = iv
      , cstMacSecret = secret
      }
    rt = RecordState {
        stCryptState  = cst
      , stMacState    = MacState { msSequence = 0 }
      , stCipher      = Just cipher
      , stCompression = nullCompression
      }

setHelloParameters13 :: Cipher -> Bool -> HandshakeM ()
setHelloParameters13 cipher isHRR = modify update
  where
    update hst = case hstPendingCipher hst of
      Nothing -> hst {
                  hstPendingCipher      = Just cipher
                , hstPendingCompression = nullCompression
                , hstHandshakeDigest    = updateDigest $ hstHandshakeDigest hst
                }
      Just oldcipher -> if cipher == oldcipher
                        then hst
                        else error "TLS 1.3: cipher changed"
    hashAlg = cipherHash cipher
    updateDigest (Left bytes) = Right $ calc $ reverse bytes
    updateDigest (Right _)    = error "cannot initialize digest with another digest"
    calc []       = error "setHelloParameters13.calc []"
    calc bbs@(b:bs)
      | isHRR     = let siz = hashDigestSize hashAlg
                        b' = B.concat [
                              "\254\0\0"
                            , B.singleton (fromIntegral siz)
                            , hash hashAlg b]
                    in foldl hashUpdate (hashInit hashAlg) (b':bs)
      | otherwise = foldl hashUpdate (hashInit hashAlg) bbs

transcriptHash :: Context -> IO ByteString
transcriptHash ctx = do
    hst <- fromJust "HState" <$> getHState ctx
    case hstHandshakeDigest hst of
      Right hashCtx -> return $ hashFinal hashCtx
      Left _        -> error "un-initialized handshake digest"

setPendingActions :: Context -> [ByteString -> IO ()] -> IO ()
setPendingActions ctx bss =
    modifyMVar_ (ctxPendingActions ctx) (\_ -> return bss)

popPendingAction :: Context -> IO (ByteString -> IO ())
popPendingAction ctx =
    modifyMVar (ctxPendingActions ctx) (\(bs:bss) -> return (bss,bs)) -- fixme
