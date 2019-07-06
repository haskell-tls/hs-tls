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
       , clearTxState
       , clearRxState
       , setHelloParameters13
       , transcriptHash
       , wrapAsMessageHash13
       , PendingAction(..)
       , setPendingActions
       , popPendingAction
       ) where

import Control.Concurrent.MVar
import Control.Monad.State
import qualified Data.ByteString as B
import Data.IORef
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

clearTxState :: Context -> IO ()
clearTxState = clearXState ctxTxState

clearRxState :: Context -> IO ()
clearRxState = clearXState ctxRxState

clearXState :: (Context -> MVar RecordState) -> Context -> IO ()
clearXState func ctx =
    modifyMVar_ (func ctx) (\rt -> return rt { stCipher = Nothing })

setHelloParameters13 :: Cipher -> HandshakeM ()
setHelloParameters13 cipher = modify update
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
    updateDigest (HandshakeMessages bytes)  = HandshakeDigestContext $ foldl hashUpdate (hashInit hashAlg) $ reverse bytes
    updateDigest (HandshakeDigestContext _) = error "cannot initialize digest with another digest"

-- When a HelloRetryRequest is sent or received, the existing transcript must be
-- wrapped in a "message_hash" construct.  See RFC 8446 section 4.4.1.  This
-- applies to key-schedule computations as well as the ones for PSK binders.
wrapAsMessageHash13 :: HandshakeM ()
wrapAsMessageHash13 = do
    cipher <- getPendingCipher
    foldHandshakeDigest (cipherHash cipher) foldFunc
  where
    foldFunc dig = B.concat [ "\254\0\0"
                            , B.singleton (fromIntegral $ B.length dig)
                            , dig
                            ]

transcriptHash :: MonadIO m => Context -> m ByteString
transcriptHash ctx = do
    hst <- fromJust "HState" <$> getHState ctx
    case hstHandshakeDigest hst of
      HandshakeDigestContext hashCtx -> return $ hashFinal hashCtx
      HandshakeMessages      _       -> error "un-initialized handshake digest"

setPendingActions :: Context -> [PendingAction] -> IO ()
setPendingActions ctx = writeIORef (ctxPendingActions ctx)

popPendingAction :: Context -> IO (Maybe PendingAction)
popPendingAction ctx = do
    let ref = ctxPendingActions ctx
    actions <- readIORef ref
    case actions of
        bs:bss -> writeIORef ref bss >> return (Just bs)
        []     -> return Nothing
