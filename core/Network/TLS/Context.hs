{-# LANGUAGE CPP #-}
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
      TLSParams

    -- * Context object and accessor
    , Context(..)
    , Hooks(..)
    , Established(..)
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

    -- * New contexts
    , contextNew
    -- * Deprecated new contexts methods
    , contextNewOnHandle
#ifdef INCLUDE_NETWORK
    , contextNewOnSocket
#endif

    -- * Context hooks
    , contextHookSetHandshakeRecv
    , contextHookSetHandshake13Recv
    , contextHookSetCertificateRecv
    , contextHookSetLogging

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
import Network.TLS.Context.Internal
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.State
import Network.TLS.Hooks
import Network.TLS.Record.State
import Network.TLS.Record.Layer
import Network.TLS.Record.Reading
import Network.TLS.Record.Writing
import Network.TLS.Parameters
import Network.TLS.Measurement
import Network.TLS.Types (Role(..))
import Network.TLS.Handshake (handshakeClient, handshakeClientWith, handshakeServer, handshakeServerWith)
import Network.TLS.PostHandshake (requestCertificateServer, postHandshakeAuthClientWith, postHandshakeAuthServerWith)
import Network.TLS.X509
import Network.TLS.RNG

import Control.Concurrent.MVar
import Control.Monad.State.Strict
import Data.IORef

-- deprecated imports
#ifdef INCLUDE_NETWORK
import Network.Socket (Socket)
#endif
import System.IO (Handle)

class TLSParams a where
    getTLSCommonParams :: a -> CommonParams
    getTLSRole         :: a -> Role
    doHandshake        :: a -> Context -> IO ()
    doHandshakeWith    :: a -> Context -> Handshake -> IO ()
    doRequestCertificate :: a -> Context -> IO Bool
    doPostHandshakeAuthWith :: a -> Context -> Handshake13 -> IO ()

instance TLSParams ClientParams where
    getTLSCommonParams cparams = ( clientSupported cparams
                                 , clientShared cparams
                                 , clientDebug cparams
                                 )
    getTLSRole _ = ClientRole
    doHandshake = handshakeClient
    doHandshakeWith = handshakeClientWith
    doRequestCertificate _ _ = return False
    doPostHandshakeAuthWith = postHandshakeAuthClientWith

instance TLSParams ServerParams where
    getTLSCommonParams sparams = ( serverSupported sparams
                                 , serverShared sparams
                                 , serverDebug sparams
                                 )
    getTLSRole _ = ServerRole
    doHandshake = handshakeServer
    doHandshakeWith = handshakeServerWith
    doRequestCertificate = requestCertificateServer
    doPostHandshakeAuthWith = postHandshakeAuthServerWith

-- | create a new context using the backend and parameters specified.
contextNew :: (MonadIO m, HasBackend backend, TLSParams params)
           => backend   -- ^ Backend abstraction with specific method to interact with the connection type.
           -> params    -- ^ Parameters of the context.
           -> m Context
contextNew backend params = liftIO $ do
    initializeBackend backend

    let (supported, shared, debug) = getTLSCommonParams params

    seed <- case debugSeed debug of
                Nothing     -> do seed <- seedNew
                                  debugPrintSeed debug seed
                                  return seed
                Just determ -> return determ
    let rng = newStateRNG seed

    let role = getTLSRole params
        st   = newTLSState rng role

    stvar <- newMVar st
    eof   <- newIORef False
    established <- newIORef NotEstablished
    stats <- newIORef newMeasurement
    -- we enable the reception of SSLv2 ClientHello message only in the
    -- server context, where we might be dealing with an old/compat client.
    sslv2Compat <- newIORef (role == ServerRole)
    needEmptyPacket <- newIORef False
    hooks <- newIORef defaultHooks
    tx    <- newMVar newRecordState
    rx    <- newMVar newRecordState
    hs    <- newMVar Nothing
    as    <- newIORef []
    crs   <- newIORef []
    lockWrite <- newMVar ()
    lockRead  <- newMVar ()
    lockState <- newMVar ()

    let ctx = Context
            { ctxConnection   = getBackend backend
            , ctxShared       = shared
            , ctxSupported    = supported
            , ctxState        = stvar
            , ctxFragmentSize = Just 16384
            , ctxTxState      = tx
            , ctxRxState      = rx
            , ctxHandshake    = hs
            , ctxDoHandshake  = doHandshake params
            , ctxDoHandshakeWith  = doHandshakeWith params
            , ctxDoRequestCertificate = doRequestCertificate params
            , ctxDoPostHandshakeAuthWith = doPostHandshakeAuthWith params
            , ctxMeasurement  = stats
            , ctxEOF_         = eof
            , ctxEstablished_ = established
            , ctxSSLv2ClientHello = sslv2Compat
            , ctxNeedEmptyPacket  = needEmptyPacket
            , ctxHooks            = hooks
            , ctxLockWrite        = lockWrite
            , ctxLockRead         = lockRead
            , ctxLockState        = lockState
            , ctxPendingActions   = as
            , ctxCertRequests     = crs
            , ctxKeyLogger        = debugKeyLogger debug
            , ctxRecordLayer      = recordLayer
            , ctxHandshakeSync    = HandshakeSync syncNoOp syncNoOp
            , ctxQUICMode         = False
            }

        syncNoOp _ _ = return ()

        recordLayer = RecordLayer
            { recordEncode    = encodeRecord ctx
            , recordEncode13  = encodeRecord13 ctx
            , recordSendBytes = sendBytes ctx
            , recordRecv      = recvRecord ctx
            , recordRecv13    = recvRecord13 ctx
            }

    return ctx

-- | create a new context on an handle.
contextNewOnHandle :: (MonadIO m, TLSParams params)
                   => Handle -- ^ Handle of the connection.
                   -> params -- ^ Parameters of the context.
                   -> m Context
contextNewOnHandle = contextNew
{-# DEPRECATED contextNewOnHandle "use contextNew" #-}

#ifdef INCLUDE_NETWORK
-- | create a new context on a socket.
contextNewOnSocket :: (MonadIO m, TLSParams params)
                   => Socket -- ^ Socket of the connection.
                   -> params -- ^ Parameters of the context.
                   -> m Context
contextNewOnSocket sock params = contextNew sock params
{-# DEPRECATED contextNewOnSocket "use contextNew" #-}
#endif

contextHookSetHandshakeRecv :: Context -> (Handshake -> IO Handshake) -> IO ()
contextHookSetHandshakeRecv context f =
    contextModifyHooks context (\hooks -> hooks { hookRecvHandshake = f })

contextHookSetHandshake13Recv :: Context -> (Handshake13 -> IO Handshake13) -> IO ()
contextHookSetHandshake13Recv context f =
    contextModifyHooks context (\hooks -> hooks { hookRecvHandshake13 = f })

contextHookSetCertificateRecv :: Context -> (CertificateChain -> IO ()) -> IO ()
contextHookSetCertificateRecv context f =
    contextModifyHooks context (\hooks -> hooks { hookRecvCertificates = f })

contextHookSetLogging :: Context -> Logging -> IO ()
contextHookSetLogging context loggingCallbacks =
    contextModifyHooks context (\hooks -> hooks { hookLogging = loggingCallbacks })
