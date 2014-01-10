-- |
-- Module      : Network.TLS.Context
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Context
    (
    -- * Context configuration
      Params(..)
    , RoleParams(..)
    , ClientParams(..)
    , ServerParams(..)
    , updateClientParams
    , updateServerParams
    , Logging(..)
    , SessionID
    , SessionData(..)
    , MaxFragmentEnum(..)
    , Measurement(..)
    , CertificateUsage(..)
    , CertificateRejectReason(..)
    , defaultLogging
    , defaultParamsClient
    , defaultParamsServer
    , withSessionManager
    , setSessionManager
    , getClientParams
    , getServerParams
    , credentialsGet

    -- * Context object and accessor
    , Context
    , Hooks(..)
    , ctxParams
    , ctxConnection
    , ctxEOF
    , ctxHasSSLv2ClientHello
    , ctxDisableSSLv2ClientHello
    , ctxEstablished
    , ctxCiphers
    , ctxLogging
    , ctxWithHooks
    , ctxRxState
    , ctxTxState
    , ctxHandshake
    , ctxNeedEmptyPacket
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

    -- * deprecated types
    , TLSParams
    , TLSLogging
    , TLSCertificateUsage
    , TLSCertificateRejectReason
    , TLSCtx

    -- * New contexts
    , contextNew
    , contextNewOnHandle
    , contextNewOnSocket

    -- * Context hooks
    , contextHookSetHandshakeRecv

    -- * Using context states
    , throwCore
    , usingState
    , usingState_
    , runTxState
    , runRxState
    , usingHState
    , getHState
    , getStateRNG
    ) where

import Network.Socket (Socket, sClose)
import qualified Network.Socket.ByteString as Socket

import Network.TLS.Backend
import Network.TLS.Extension
import Network.TLS.Struct
import Network.TLS.Cipher
import Network.TLS.Credentials
import Network.TLS.State
import Network.TLS.Handshake.State
import Network.TLS.Hooks
import Network.TLS.Record.State
import Network.TLS.Parameters
import Network.TLS.Measurement
import Network.TLS.Types (Role(..))
import Data.Maybe (isJust)
import qualified Data.ByteString as B

import Crypto.Random

import Control.Concurrent.MVar
import Control.Monad.State
import Control.Exception (throwIO, Exception())
import Data.IORef
import Data.Tuple
import System.IO (Handle, hSetBuffering, BufferMode(..), hFlush, hClose)


-- | A TLS Context keep tls specific state, parameters and backend information.
data Context = Context
    { ctxConnection       :: Backend   -- ^ return the backend object associated with this context
    , ctxParams           :: Params
    , ctxCiphers          :: [Cipher]  -- ^ prepared list of allowed ciphers according to parameters
    , ctxState            :: MVar TLSState
    , ctxMeasurement      :: IORef Measurement
    , ctxEOF_             :: IORef Bool    -- ^ has the handle EOFed or not.
    , ctxEstablished_     :: IORef Bool    -- ^ has the handshake been done and been successful.
    , ctxNeedEmptyPacket  :: IORef Bool    -- ^ empty packet workaround for CBC guessability.
    , ctxSSLv2ClientHello :: IORef Bool    -- ^ enable the reception of compatibility SSLv2 client hello.
                                           -- the flag will be set to false regardless of its initial value
                                           -- after the first packet received.
    , ctxTxState          :: MVar RecordState -- ^ current tx state
    , ctxRxState          :: MVar RecordState -- ^ current rx state
    , ctxHandshake        :: MVar (Maybe HandshakeState) -- ^ optional handshake state
    , ctxHooks            :: IORef Hooks   -- ^ hooks for this context
    , ctxLockWrite        :: MVar ()       -- ^ lock to use for writing data (including updating the state)
    , ctxLockRead         :: MVar ()       -- ^ lock to use for reading data (including updating the state)
    , ctxLockState        :: MVar ()       -- ^ lock used during read/write when receiving and sending packet.
                                           -- it is usually nested in a write or read lock.
    }

-- deprecated types, setup as aliases for compatibility.
type TLSParams = Params
type TLSCtx = Context
type TLSLogging = Logging
type TLSCertificateUsage = CertificateUsage
type TLSCertificateRejectReason = CertificateRejectReason

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

contextSend :: Context -> Bytes -> IO ()
contextSend c b = updateMeasure c (addBytesSent $ B.length b) >> (backendSend $ ctxConnection c) b

contextRecv :: Context -> Int -> IO Bytes
contextRecv c sz = updateMeasure c (addBytesReceived sz) >> (backendRecv $ ctxConnection c) sz

ctxEOF :: Context -> IO Bool
ctxEOF ctx = readIORef $ ctxEOF_ ctx

ctxHasSSLv2ClientHello :: Context -> IO Bool
ctxHasSSLv2ClientHello ctx = readIORef $ ctxSSLv2ClientHello ctx

ctxDisableSSLv2ClientHello :: Context -> IO ()
ctxDisableSSLv2ClientHello ctx = writeIORef (ctxSSLv2ClientHello ctx) False

setEOF :: Context -> IO ()
setEOF ctx = writeIORef (ctxEOF_ ctx) True

ctxEstablished :: Context -> IO Bool
ctxEstablished ctx = readIORef $ ctxEstablished_ ctx

ctxWithHooks :: Context -> (Hooks -> IO a) -> IO a
ctxWithHooks ctx f = readIORef (ctxHooks ctx) >>= f

setEstablished :: Context -> Bool -> IO ()
setEstablished ctx v = writeIORef (ctxEstablished_ ctx) v

ctxLogging :: Context -> Logging
ctxLogging = pLogging . ctxParams

-- | create a new context using the backend and parameters specified.
contextNew :: (MonadIO m, CPRG rng, HasBackend backend)
           => backend   -- ^ Backend abstraction with specific method to interact with the connection type.
           -> Params    -- ^ Parameters of the context.
           -> rng       -- ^ Random number generator associated with this context.
           -> m Context
contextNew backend params rng = liftIO $ do
    let role = case roleParams params of
                    Client {} -> ClientRole
                    Server {} -> ServerRole
    let st = newTLSState rng role

    stvar <- newMVar st
    eof   <- newIORef False
    established <- newIORef False
    stats <- newIORef newMeasurement
    -- we enable the reception of SSLv2 ClientHello message only in the
    -- server context, where we might be dealing with an old/compat client.
    sslv2Compat <- newIORef (role == ServerRole)
    needEmptyPacket <- newIORef False
    hooks <- newIORef defaultHooks
    tx    <- newMVar newRecordState
    rx    <- newMVar newRecordState
    hs    <- newMVar Nothing
    -- on the server we filter our allowed ciphers here according
    -- to the credentials and DHE parameters loaded
    let ciphers = case roleParams params of
                    Client {}      -> pCiphers params
                    Server sParams -> filterServer sParams $ pCiphers params
    lockWrite <- newMVar ()
    lockRead  <- newMVar ()
    lockState <- newMVar ()

    when (null ciphers) $ error "no ciphers available with those parameters"

    return $ Context
            { ctxConnection   = getBackend backend
            , ctxParams       = params
            , ctxCiphers      = ciphers
            , ctxState        = stvar
            , ctxTxState      = tx
            , ctxRxState      = rx
            , ctxHandshake    = hs
            , ctxMeasurement  = stats
            , ctxEOF_         = eof
            , ctxEstablished_ = established
            , ctxSSLv2ClientHello = sslv2Compat
            , ctxNeedEmptyPacket  = needEmptyPacket
            , ctxHooks            = hooks
            , ctxLockWrite        = lockWrite
            , ctxLockRead         = lockRead
            , ctxLockState        = lockState
            }
  where filterServer sParams ciphers = filter authorizedCKE ciphers
          where authorizedCKE cipher =
                    case cipherKeyExchange cipher of
                        CipherKeyExchange_RSA         -> canEncryptRSA
                        CipherKeyExchange_DH_Anon     -> canDHE
                        CipherKeyExchange_DHE_RSA     -> canSignRSA && canDHE
                        CipherKeyExchange_DHE_DSS     -> canSignDSS && canDHE
                        -- unimplemented: non ephemeral DH
                        CipherKeyExchange_DH_DSS      -> False
                        CipherKeyExchange_DH_RSA      -> False
                        -- unimplemented: EC
                        CipherKeyExchange_ECDHE_RSA   -> False
                        CipherKeyExchange_ECDH_ECDSA  -> False
                        CipherKeyExchange_ECDH_RSA    -> False
                        CipherKeyExchange_ECDHE_ECDSA -> False

                canDHE        = isJust $ serverDHEParams sParams
                canSignDSS    = SignatureDSS `elem` signingAlgs
                canSignRSA    = SignatureRSA `elem` signingAlgs
                canEncryptRSA = isJust $ credentialsFindForDecrypting creds
                signingAlgs   = credentialsListSigningAlgorithms creds
                creds         = credentialsGet params

-- | create a new context on an handle.
contextNewOnHandle :: (MonadIO m, CPRG rng)
                   => Handle -- ^ Handle of the connection.
                   -> Params -- ^ Parameters of the context.
                   -> rng    -- ^ Random number generator associated with this context.
                   -> m Context
contextNewOnHandle handle params st =
    liftIO (hSetBuffering handle NoBuffering) >> contextNew backend params st
  where backend = Backend (hFlush handle) (hClose handle) (B.hPut handle) (B.hGet handle)

-- | create a new context on a socket.
contextNewOnSocket :: (MonadIO m, CPRG rng)
                   => Socket -- ^ Socket of the connection.
                   -> Params -- ^ Parameters of the context.
                   -> rng    -- ^ Random number generator associated with this context.
                   -> m Context
contextNewOnSocket sock params st = contextNew backend params st
  where backend   = Backend (return ()) (sClose sock) (Socket.sendAll sock) recvAll
        recvAll n = B.concat `fmap` loop n
          where loop 0    = return []
                loop left = do
                    r <- Socket.recv sock left
                    liftM (r:) (loop (left - B.length r))

contextHookSetHandshakeRecv :: Context -> (Handshake -> IO Handshake) -> IO ()
contextHookSetHandshakeRecv context f =
    liftIO $ modifyIORef (ctxHooks context) (\hooks -> hooks { hookRecvHandshake = f })

throwCore :: (MonadIO m, Exception e) => e -> m a
throwCore = liftIO . throwIO

usingState :: Context -> TLSSt a -> IO (Either TLSError a)
usingState ctx f =
    modifyMVar (ctxState ctx) $ \st ->
            let (a, newst) = runTLSState f st
             in newst `seq` return (newst, a)

usingState_ :: Context -> TLSSt a -> IO a
usingState_ ctx f = do
    ret <- usingState ctx f
    case ret of
        Left err -> throwCore err
        Right r  -> return r

usingHState :: Context -> HandshakeM a -> IO a
usingHState ctx f = liftIO $ modifyMVar (ctxHandshake ctx) $ \mst ->
    case mst of
        Nothing -> throwCore $ Error_Misc "missing handshake"
        Just st -> return $ swap (Just `fmap` runHandshake st f)

getHState :: Context -> IO (Maybe HandshakeState)
getHState ctx = liftIO $ readMVar (ctxHandshake ctx)

runTxState :: Context -> RecordM a -> IO (Either TLSError a)
runTxState ctx f = do
    ver <- usingState_ ctx (getVersionWithDefault $ pConnectVersion $ ctxParams ctx)
    modifyMVar (ctxTxState ctx) $ \st ->
        case runRecordM f ver st of
            Left err         -> return (st, Left err)
            Right (a, newSt) -> return (newSt, Right a)

runRxState :: Context -> RecordM a -> IO (Either TLSError a)
runRxState ctx f = do
    ver <- usingState_ ctx getVersion
    modifyMVar (ctxRxState ctx) $ \st ->
        case runRecordM f ver st of
            Left err         -> return (st, Left err)
            Right (a, newSt) -> return (newSt, Right a)

getStateRNG :: Context -> Int -> IO Bytes
getStateRNG ctx n = usingState_ ctx $ genRandom n

withReadLock :: Context -> IO a -> IO a
withReadLock ctx f = withMVar (ctxLockRead ctx) (const f)

withWriteLock :: Context -> IO a -> IO a
withWriteLock ctx f = withMVar (ctxLockWrite ctx) (const f)

withRWLock :: Context -> IO a -> IO a
withRWLock ctx f = withReadLock ctx $ withWriteLock ctx f

withStateLock :: Context -> IO a -> IO a
withStateLock ctx f = withMVar (ctxLockState ctx) (const f)
