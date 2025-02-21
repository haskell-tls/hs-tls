{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.State13 (
    CryptLevel (
        CryptEarlySecret,
        CryptHandshakeSecret,
        CryptApplicationSecret
    ),
    TrafficSecret,
    getTxRecordState,
    getRxRecordState,
    setTxRecordState,
    setRxRecordState,
    getTxLevel,
    getRxLevel,
    clearTxRecordState,
    clearRxRecordState,
    transcriptHash,
    transcriptHashWith,
    updateTranscriptHash13HRR,
    PendingRecvAction (..),
    setPendingRecvActions,
    popPendingRecvAction,
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
import Network.TLS.Imports
import Network.TLS.KeySchedule (hkdfExpandLabel)
import Network.TLS.Record.State
import Network.TLS.Struct
import Network.TLS.Types

getTxRecordState :: Context -> IO (Hash, Cipher, CryptLevel, ByteString)
getTxRecordState ctx = getXState ctx ctxTxRecordState

getRxRecordState :: Context -> IO (Hash, Cipher, CryptLevel, ByteString)
getRxRecordState ctx = getXState ctx ctxRxRecordState

getXState
    :: Context
    -> (Context -> MVar RecordState)
    -> IO (Hash, Cipher, CryptLevel, ByteString)
getXState ctx func = do
    tx <- readMVar (func ctx)
    let usedCipher = fromJust $ stCipher tx
        usedHash = cipherHash usedCipher
        level = stCryptLevel tx
        secret = cstMacSecret $ stCryptState tx
    return (usedHash, usedCipher, level, secret)

-- In the case of QUIC, stCipher is Nothing.
-- So, fromJust causes an error.
getTxLevel :: Context -> IO CryptLevel
getTxLevel ctx = getXLevel ctx ctxTxRecordState

getRxLevel :: Context -> IO CryptLevel
getRxLevel ctx = getXLevel ctx ctxRxRecordState

getXLevel
    :: Context
    -> (Context -> MVar RecordState)
    -> IO CryptLevel
getXLevel ctx func = do
    tx <- readMVar (func ctx)
    return $ stCryptLevel tx

class TrafficSecret ty where
    fromTrafficSecret :: ty -> (CryptLevel, ByteString)

instance HasCryptLevel a => TrafficSecret (AnyTrafficSecret a) where
    fromTrafficSecret prx@(AnyTrafficSecret s) = (getCryptLevel prx, s)

instance HasCryptLevel a => TrafficSecret (ClientTrafficSecret a) where
    fromTrafficSecret prx@(ClientTrafficSecret s) = (getCryptLevel prx, s)

instance HasCryptLevel a => TrafficSecret (ServerTrafficSecret a) where
    fromTrafficSecret prx@(ServerTrafficSecret s) = (getCryptLevel prx, s)

setTxRecordState :: TrafficSecret ty => Context -> Hash -> Cipher -> ty -> IO ()
setTxRecordState = setXState ctxTxRecordState BulkEncrypt

setRxRecordState :: TrafficSecret ty => Context -> Hash -> Cipher -> ty -> IO ()
setRxRecordState = setXState ctxRxRecordState BulkDecrypt

setXState
    :: TrafficSecret ty
    => (Context -> MVar RecordState)
    -> BulkDirection
    -> Context
    -> Hash
    -> Cipher
    -> ty
    -> IO ()
setXState func encOrDec ctx h cipher ts =
    let (lvl, secret) = fromTrafficSecret ts
     in setXState' func encOrDec ctx h cipher lvl secret

setXState'
    :: (Context -> MVar RecordState)
    -> BulkDirection
    -> Context
    -> Hash
    -> Cipher
    -> CryptLevel
    -> ByteString
    -> IO ()
setXState' func encOrDec ctx h cipher lvl secret =
    modifyMVar_ (func ctx) (\_ -> return rt)
  where
    bulk = cipherBulk cipher
    keySize = bulkKeySize bulk
    ivSize = max 8 (bulkIVSize bulk + bulkExplicitIV bulk)
    key = hkdfExpandLabel h secret "key" "" keySize
    iv = hkdfExpandLabel h secret "iv" "" ivSize
    cst =
        CryptState
            { cstKey = bulkInit bulk encOrDec key
            , cstIV = iv
            , cstMacSecret = secret
            }
    rt =
        RecordState
            { stCryptState = cst
            , stMacState = MacState{msSequence = 0}
            , stCryptLevel = lvl
            , stCipher = Just cipher
            , stCompression = nullCompression
            }

clearTxRecordState :: Context -> IO ()
clearTxRecordState = clearXState ctxTxRecordState

clearRxRecordState :: Context -> IO ()
clearRxRecordState = clearXState ctxRxRecordState

clearXState :: (Context -> MVar RecordState) -> Context -> IO ()
clearXState func ctx =
    modifyMVar_ (func ctx) (\rt -> return rt{stCipher = Nothing})

-- When a HelloRetryRequest is sent or received, the existing transcript must be
-- wrapped in a "message_hash" construct.  See RFC 8446 section 4.4.1.  This
-- applies to key-schedule computations as well as the ones for PSK binders.
updateTranscriptHash13HRR :: HandshakeM ()
updateTranscriptHash13HRR = do
    cipher <- getPendingCipher
    foldTranscriptHash (cipherHash cipher) foldFunc
  where
    foldFunc dig =
        -- Handshake message:
        -- typ <-len-> body
        -- 254 0 0 len hash(CH1)
        B.concat
            [ "\254\0\0"
            , B.singleton (fromIntegral $ B.length dig)
            , dig
            ]

transcriptHash :: MonadIO m => Context -> m ByteString
transcriptHash ctx = do
    hst <- fromJust <$> getHState ctx
    case hstTranscriptHash hst of
        TranscriptHashContext hashCtx -> return $ hashFinal hashCtx
        HandshakeMessages _ -> error "un-initialized handshake digest"

transcriptHashWith :: MonadIO m => Context -> ByteString -> m ByteString
transcriptHashWith ctx bs = do
    hst <- fromJust <$> getHState ctx
    case hstTranscriptHash hst of
        TranscriptHashContext hashCtx -> return $ hashFinal $ hashUpdate hashCtx bs
        HandshakeMessages _ -> error "un-initialized handshake digest"

setPendingRecvActions :: Context -> [PendingRecvAction] -> IO ()
setPendingRecvActions ctx = writeIORef (ctxPendingRecvActions ctx)

popPendingRecvAction :: Context -> IO (Maybe PendingRecvAction)
popPendingRecvAction ctx = do
    let ref = ctxPendingRecvActions ctx
    actions <- readIORef ref
    case actions of
        bs : bss -> writeIORef ref bss >> return (Just bs)
        [] -> return Nothing
