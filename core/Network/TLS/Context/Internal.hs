{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Network.TLS.Context.Internal
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Context.Internal
    (
    -- * Context configuration
      ClientParams(..)
    , ServerParams(..)
    , defaultParamsClient
    , SessionID
    , SessionData(..)
    , MaxFragmentEnum(..)
    , Measurement(..)

    -- * Context object and accessor
    , Context(..)
    , Hooks(..)
    , Established(..)
    , PendingAction
    , ctxEOF
    , ctxHasSSLv2ClientHello
    , ctxDisableSSLv2ClientHello
    , ctxEstablished
    , withLog
    , ctxWithHooks
    , contextModifyHooks
    , setEOF
    , setEstablished
    , contextFlush
    , contextClose
    , contextSend
    , contextRecv
    , updateMeasure
    , withMeasure
    , withReadLock
    , withWriteLock
    , withStateLock
    , withRWLock

    -- * information
    , Information(..)
    , contextGetInformation

    -- * Using context states
    , throwCore
    , usingState
    , usingState_
    , runTxState
    , runRxState
    , usingHState
    , getHState
    , getStateRNG
    , tls13orLater
    ) where

import Network.TLS.Backend
import Network.TLS.Extension
import Network.TLS.Cipher
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Compression (Compression)
import Network.TLS.State
import Network.TLS.Handshake.State
import Network.TLS.Hooks
import Network.TLS.Record.State
import Network.TLS.Parameters
import Network.TLS.Measurement
import Network.TLS.Imports
import qualified Data.ByteString as B

import Control.Concurrent.MVar
import Control.Monad.State.Strict
import Control.Exception (throwIO, Exception())
import Data.IORef
import Data.Tuple


-- | Information related to a running context, e.g. current cipher
data Information = Information
    { infoVersion      :: Version
    , infoCipher       :: Cipher
    , infoCompression  :: Compression
    , infoMasterSecret :: Maybe ByteString
    , infoClientRandom :: Maybe ClientRandom
    , infoServerRandom :: Maybe ServerRandom
    , infoNegotiatedGroup     :: Maybe Group
    , infoTLS13HandshakeMode  :: Maybe HandshakeMode13
    , infoIsEarlyDataAccepted :: Bool
    } deriving (Show,Eq)

-- | A TLS Context keep tls specific state, parameters and backend information.
data Context = Context
    { ctxConnection       :: Backend   -- ^ return the backend object associated with this context
    , ctxSupported        :: Supported
    , ctxShared           :: Shared
    , ctxState            :: MVar TLSState
    , ctxMeasurement      :: IORef Measurement
    , ctxEOF_             :: IORef Bool    -- ^ has the handle EOFed or not.
    , ctxEstablished_     :: IORef Established -- ^ has the handshake been done and been successful.
    , ctxNeedEmptyPacket  :: IORef Bool    -- ^ empty packet workaround for CBC guessability.
    , ctxSSLv2ClientHello :: IORef Bool    -- ^ enable the reception of compatibility SSLv2 client hello.
                                           -- the flag will be set to false regardless of its initial value
                                           -- after the first packet received.
    , ctxTxState          :: MVar RecordState -- ^ current tx state
    , ctxRxState          :: MVar RecordState -- ^ current rx state
    , ctxHandshake        :: MVar (Maybe HandshakeState) -- ^ optional handshake state
    , ctxDoHandshake      :: Context -> IO ()
    , ctxDoHandshakeWith  :: Context -> Handshake -> IO ()
    , ctxHooks            :: IORef Hooks   -- ^ hooks for this context
    , ctxLockWrite        :: MVar ()       -- ^ lock to use for writing data (including updating the state)
    , ctxLockRead         :: MVar ()       -- ^ lock to use for reading data (including updating the state)
    , ctxLockState        :: MVar ()       -- ^ lock used during read/write when receiving and sending packet.
                                           -- it is usually nested in a write or read lock.
    , ctxPendingActions   :: IORef [PendingAction]
    , ctxKeyLogger        :: String -> IO ()
    }

data Established = NotEstablished
                 | EarlyDataAllowed Int    -- remaining 0-RTT bytes allowed
                 | EarlyDataNotAllowed Int -- remaining 0-RTT packets allowed to skip
                 | Established
                 deriving (Eq, Show)

type PendingAction = (Handshake13 -> IO (), IO ())

updateMeasure :: Context -> (Measurement -> Measurement) -> IO ()
updateMeasure ctx f = do
    x <- readIORef (ctxMeasurement ctx)
    writeIORef (ctxMeasurement ctx) $! f x

withMeasure :: Context -> (Measurement -> IO a) -> IO a
withMeasure ctx f = readIORef (ctxMeasurement ctx) >>= f

contextFlush :: Context -> IO ()
contextFlush = backendFlush . ctxConnection

contextClose :: Context -> IO ()
contextClose = backendClose . ctxConnection

-- | Information about the current context
contextGetInformation :: Context -> IO (Maybe Information)
contextGetInformation ctx = do
    ver    <- usingState_ ctx $ gets stVersion
    hstate <- getHState ctx
    let (ms, cr, sr, hm13, grp) = case hstate of
                           Just st -> (hstMasterSecret st,
                                       Just (hstClientRandom st),
                                       hstServerRandom st,
                                       if ver == Just TLS13 then Just (hstTLS13HandshakeMode st) else Nothing,
                                       hstNegotiatedGroup st)
                           Nothing -> (Nothing, Nothing, Nothing, Nothing, Nothing)
    (cipher,comp) <- failOnEitherError $ runRxState ctx $ gets $ \st -> (stCipher st, stCompression st)
    let accepted = case hstate of
            Just st -> hstTLS13RTT0Status st == RTT0Accepted
            Nothing -> False
    case (ver, cipher) of
        (Just v, Just c) -> return $ Just $ Information v c comp ms cr sr grp hm13 accepted
        _                -> return Nothing

contextSend :: Context -> ByteString -> IO ()
contextSend c b = updateMeasure c (addBytesSent $ B.length b) >> (backendSend $ ctxConnection c) b

contextRecv :: Context -> Int -> IO ByteString
contextRecv c sz = updateMeasure c (addBytesReceived sz) >> (backendRecv $ ctxConnection c) sz

ctxEOF :: Context -> IO Bool
ctxEOF ctx = readIORef $ ctxEOF_ ctx

ctxHasSSLv2ClientHello :: Context -> IO Bool
ctxHasSSLv2ClientHello ctx = readIORef $ ctxSSLv2ClientHello ctx

ctxDisableSSLv2ClientHello :: Context -> IO ()
ctxDisableSSLv2ClientHello ctx = writeIORef (ctxSSLv2ClientHello ctx) False

setEOF :: Context -> IO ()
setEOF ctx = writeIORef (ctxEOF_ ctx) True

ctxEstablished :: Context -> IO Established
ctxEstablished ctx = readIORef $ ctxEstablished_ ctx

ctxWithHooks :: Context -> (Hooks -> IO a) -> IO a
ctxWithHooks ctx f = readIORef (ctxHooks ctx) >>= f

contextModifyHooks :: Context -> (Hooks -> Hooks) -> IO ()
contextModifyHooks ctx = modifyIORef (ctxHooks ctx)

setEstablished :: Context -> Established -> IO ()
setEstablished ctx = writeIORef (ctxEstablished_ ctx)

withLog :: Context -> (Logging -> IO ()) -> IO ()
withLog ctx f = ctxWithHooks ctx (f . hookLogging)

throwCore :: (MonadIO m, Exception e) => e -> m a
throwCore = liftIO . throwIO

failOnEitherError :: MonadIO m => m (Either TLSError a) -> m a
failOnEitherError f = do
    ret <- f
    case ret of
        Left err -> throwCore err
        Right r  -> return r

usingState :: Context -> TLSSt a -> IO (Either TLSError a)
usingState ctx f =
    modifyMVar (ctxState ctx) $ \st ->
            let (a, newst) = runTLSState f st
             in newst `seq` return (newst, a)

usingState_ :: Context -> TLSSt a -> IO a
usingState_ ctx f = failOnEitherError $ usingState ctx f

usingHState :: MonadIO m => Context -> HandshakeM a -> m a
usingHState ctx f = liftIO $ modifyMVar (ctxHandshake ctx) $ \mst ->
    case mst of
        Nothing -> throwCore $ Error_Misc "missing handshake"
        Just st -> return $ swap (Just <$> runHandshake st f)

getHState :: MonadIO m => Context -> m (Maybe HandshakeState)
getHState ctx = liftIO $ readMVar (ctxHandshake ctx)

runTxState :: Context -> RecordM a -> IO (Either TLSError a)
runTxState ctx f = do
    ver <- usingState_ ctx (getVersionWithDefault $ maximum $ supportedVersions $ ctxSupported ctx)
    hrr <- usingState_ ctx getTLS13HRR
    -- For TLS 1.3, ver' is only used in ClientHello.
    -- The record version of the first ClientHello SHOULD be TLS 1.0.
    -- The record version of the second ClientHello MUST be TLS 1.2.
    let ver'
         | ver >= TLS13 = if hrr then TLS12 else TLS10
         | otherwise    = ver
    modifyMVar (ctxTxState ctx) $ \st ->
        case runRecordM f ver' st of
            Left err         -> return (st, Left err)
            Right (a, newSt) -> return (newSt, Right a)

runRxState :: Context -> RecordM a -> IO (Either TLSError a)
runRxState ctx f = do
    ver <- usingState_ ctx getVersion
    -- For 1.3, ver is just ignored. So, it is not necessary to convert ver.
    modifyMVar (ctxRxState ctx) $ \st ->
        case runRecordM f ver st of
            Left err         -> return (st, Left err)
            Right (a, newSt) -> return (newSt, Right a)

getStateRNG :: Context -> Int -> IO ByteString
getStateRNG ctx n = usingState_ ctx $ genRandom n

withReadLock :: Context -> IO a -> IO a
withReadLock ctx f = withMVar (ctxLockRead ctx) (const f)

withWriteLock :: Context -> IO a -> IO a
withWriteLock ctx f = withMVar (ctxLockWrite ctx) (const f)

withRWLock :: Context -> IO a -> IO a
withRWLock ctx f = withReadLock ctx $ withWriteLock ctx f

withStateLock :: Context -> IO a -> IO a
withStateLock ctx f = withMVar (ctxLockState ctx) (const f)

tls13orLater :: MonadIO m => Context -> m Bool
tls13orLater ctx = do
    ev <- liftIO $ usingState ctx $ getVersionWithDefault TLS10 -- fixme
    return $ case ev of
               Left  _ -> False
               Right v -> v >= TLS13
