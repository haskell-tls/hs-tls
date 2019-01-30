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
      TLSParams(..)

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
import Network.TLS.State
import Network.TLS.Hooks
import Network.TLS.Record.State
import Network.TLS.Parameters
import Network.TLS.Measurement
import Network.TLS.Types (Role(..))
import Network.TLS.Handshake (handshakeClient, handshakeClientWith, handshakeServer, handshakeServerWith)
import Network.TLS.X509
import Network.TLS.RNG

import Control.Concurrent.MVar
import Control.Monad.State.Strict

import Data.IORef
import Crypto.Random
import Time.System
import Time.Types
import Data.Serialize
import Data.Tuple(swap)
import qualified Crypto.MAC.HMAC as HMAC
import Crypto.Hash.Algorithms(MD5)
import qualified Data.ByteString as B
import qualified Data.ByteArray as BA

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

instance TLSParams ClientParams where
    getTLSCommonParams cparams = ( clientSupported cparams
                                 , clientShared cparams
                                 , clientDebug cparams
                                 )
    getTLSRole _ = ClientRole
    doHandshake = handshakeClient
    doHandshakeWith = handshakeClientWith

instance TLSParams ServerParams where
    getTLSCommonParams sparams = ( serverSupported sparams
                                 , serverShared sparams
                                 , serverDebug sparams
                                 )
    getTLSRole _ = ServerRole
    doHandshake = handshakeServer
    doHandshakeWith = handshakeServerWith

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
    lockWrite <- newMVar ()
    lockRead  <- newMVar ()
    lockState <- newMVar ()
    (cookieGen, cookieVerify) <- makeHelloCookieMethods
    hsMsgSeq <- newIORef 0

    return Context
            { ctxConnection   = getBackend backend
            , ctxShared       = shared
            , ctxSupported    = supported
            , ctxState        = stvar
            , ctxTxState      = tx
            , ctxRxState      = rx
            , ctxHandshake    = hs
            , ctxDoHandshake  = doHandshake params
            , ctxDoHandshakeWith  = doHandshakeWith params
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
            , ctxKeyLogger        = debugKeyLogger debug
            , ctxMTU              = 1024
            , ctxHelloCookieGen   = cookieGen
            , ctxHelloCookieVerify= cookieVerify
            , ctxNextHsMsgSeq     = \count -> atomicModifyIORef' r (\sn -> (sn+count, [sn..sn+count-1]))
            }

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

contextHookSetCertificateRecv :: Context -> (CertificateChain -> IO ()) -> IO ()
contextHookSetCertificateRecv context f =
    contextModifyHooks context (\hooks -> hooks { hookRecvCertificates = f })

contextHookSetLogging :: Context -> Logging -> IO ()
contextHookSetLogging context loggingCallbacks =
    contextModifyHooks context (\hooks -> hooks { hookLogging = loggingCallbacks })


makeHelloCookieMethods :: IO (IO HelloCookie, HelloCookie -> IO Bool)
-- Returns two methods -- one to generate and other to verify a cookie that is
-- to be placed in HelloVerifyRequest hanshake message.
-- This implementation suffers from the fact that we don't have the information
-- on peer IP address here, so we cannot be sure each peer uses only its own cookie.
-- 
-- So there'll be just a time window of cOOKIE_EXPIRATION_TIMEOUT
-- during which cookies are valid. And of course a random salt in each cookie, but
-- no binding of a cookie with the peer for whom it was generated.
makeHelloCookieMethods = do
    let cOOKIE_EXPIRATION_TIMEOUT = 4 -- seconds
    rng <- getSystemDRG >>= newIORef
    let mkrandom :: Int -> IO B.ByteString
        mkrandom bytes = atomicModifyIORef' rng $ swap . randomBytesGenerate bytes
    secret <- mkrandom 16
    let generate = do
          (Elapsed (Seconds ts)) <- timeCurrent
          let tsbs = encode ts
          salt <- mkrandom 8
          let mac :: HMAC.HMAC MD5
              mac = HMAC.hmac secret $ salt <> tsbs
          return $ HelloCookie $ salt <> tsbs <> (BA.convert $ HMAC.hmacGetDigest mac)
        verify (HelloCookie cbs) = do
          (Elapsed (Seconds ts')) <- timeCurrent
          let (salt, r) = B.splitAt 8 cbs
              (tsbs, mac') = B.splitAt 8 r
              ets = decode tsbs
              mac :: HMAC.HMAC MD5
              mac = HMAC.hmac secret $ salt <> tsbs
              macVerified = (BA.convert mac) == mac'
          case ets of
            Left _ -> return False
            Right ts -> return $ macVerified &&
                        (abs (ts - ts') <= cOOKIE_EXPIRATION_TIMEOUT)
    return (generate, verify)
