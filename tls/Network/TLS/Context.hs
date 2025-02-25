{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Context (
    -- * Context configuration
    TLSParams,

    -- * Context object and accessor
    Context (..),
    Hooks (..),
    Established (..),
    RecordLayer (..),
    ctxEOF,
    ctxEstablished,
    withLog,
    ctxWithHooks,
    contextModifyHooks,
    setEOF,
    setEstablished,
    contextFlush,
    contextClose,
    contextSend,
    contextRecv,
    updateMeasure,
    withMeasure,
    withReadLock,
    withWriteLock,
    withStateLock,
    withRWLock,

    -- * information
    Information (..),
    contextGetInformation,

    -- * New contexts
    contextNew,

    -- * Context hooks
    contextHookSetHandshakeRecv,
    contextHookSetHandshake13Recv,
    contextHookSetCertificateRecv,
    contextHookSetLogging,

    -- * Using context states
    throwCore,
    usingState,
    usingState_,
    runTxRecordState,
    runRxRecordState,
    usingHState,
    getHState,
    getStateRNG,
    tls13orLater,
    getTLSUnique,
    getTLSExporter,
    getTLSServerEndPoint,
    getFinished,
    getPeerFinished,
    TLS13State (..),
    getTLS13State,
    modifyTLS13State,
    setMyRecordLimit,
    enableMyRecordLimit,
    getMyRecordLimit,
    checkMyRecordLimit,
    setPeerRecordLimit,
    enablePeerRecordLimit,
    getPeerRecordLimit,
    checkPeerRecordLimit,
    newRecordLimitRef,
) where

import Control.Concurrent.MVar
import Control.Monad.State.Strict
import Data.IORef

import Network.TLS.Backend
import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Handshake (
    handshakeClient,
    handshakeClientWith,
    handshakeServer,
    handshakeServerWith,
 )
import Network.TLS.Handshake.State13
import Network.TLS.Hooks
import Network.TLS.Imports
import Network.TLS.KeySchedule
import Network.TLS.Measurement
import Network.TLS.Packet
import Network.TLS.Parameters
import Network.TLS.PostHandshake (
    postHandshakeAuthClientWith,
    postHandshakeAuthServerWith,
    requestCertificateServer,
 )
import Network.TLS.RNG
import Network.TLS.Record.Recv
import Network.TLS.Record.Send
import Network.TLS.Record.State
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types (Role (..), defaultRecordSizeLimit)
import Network.TLS.X509

class TLSParams a where
    getTLSCommonParams :: a -> CommonParams
    getTLSRole :: a -> Role
    doHandshake :: a -> Context -> IO ()
    doHandshakeWith :: a -> Context -> Handshake -> IO ()
    doRequestCertificate :: a -> Context -> IO Bool
    doPostHandshakeAuthWith :: a -> Context -> Handshake13 -> IO ()

instance TLSParams ClientParams where
    getTLSCommonParams cparams =
        ( clientSupported cparams
        , clientShared cparams
        , clientDebug cparams
        )
    getTLSRole _ = ClientRole
    doHandshake = handshakeClient
    doHandshakeWith = handshakeClientWith
    doRequestCertificate _ _ = return False
    doPostHandshakeAuthWith = postHandshakeAuthClientWith

instance TLSParams ServerParams where
    getTLSCommonParams sparams =
        ( serverSupported sparams
        , serverShared sparams
        , serverDebug sparams
        )
    getTLSRole _ = ServerRole
    doHandshake = handshakeServer
    doHandshakeWith = handshakeServerWith
    doRequestCertificate = requestCertificateServer
    doPostHandshakeAuthWith = postHandshakeAuthServerWith

-- | create a new context using the backend and parameters specified.
contextNew
    :: (MonadIO m, HasBackend backend, TLSParams params)
    => backend
    -- ^ Backend abstraction with specific method to interact with the connection type.
    -> params
    -- ^ Parameters of the context.
    -> m Context
contextNew backend params = liftIO $ do
    initializeBackend backend

    let (supported, shared, debug) = getTLSCommonParams params

    seed <- case debugSeed debug of
        Nothing -> do
            seed <- seedNew
            debugPrintSeed debug seed
            return seed
        Just determ -> return determ
    let rng = newStateRNG seed

    let role = getTLSRole params
        st = newTLSState rng role

    tlsstate <- newMVar st
    eof <- newIORef False
    established <- newIORef NotEstablished
    stats <- newIORef newMeasurement
    needEmptyPacket <- newIORef False
    hooks <- newIORef defaultHooks
    tx <- newMVar newRecordState
    rx <- newMVar newRecordState
    hs <- newMVar Nothing
    recvActionsRef <- newIORef []
    sendActionRef <- newIORef Nothing
    crs <- newIORef []
    locks <- Locks <$> newMVar () <*> newMVar () <*> newMVar ()
    st13ref <- newIORef defaultTLS13State
    mylimref <- newRecordLimitRef $ Just defaultRecordSizeLimit
    peerlimref <- newRecordLimitRef $ Just defaultRecordSizeLimit
    let roleParams =
            RoleParams
                { doHandshake_ = doHandshake params
                , doHandshakeWith_ = doHandshakeWith params
                , doRequestCertificate_ = doRequestCertificate params
                , doPostHandshakeAuthWith_ = doPostHandshakeAuthWith params
                }

    let ctx =
            Context
                { ctxBackend = getBackend backend
                , ctxShared = shared
                , ctxSupported = supported
                , ctxTLSState = tlsstate
                , ctxMyRecordLimit = mylimref
                , ctxPeerRecordLimit = peerlimref
                , ctxTxRecordState = tx
                , ctxRxRecordState = rx
                , ctxHandshakeState = hs
                , ctxRoleParams = roleParams
                , ctxMeasurement = stats
                , ctxEOF_ = eof
                , ctxEstablished_ = established
                , ctxNeedEmptyPacket = needEmptyPacket
                , ctxHooks = hooks
                , ctxLocks = locks
                , ctxPendingRecvActions = recvActionsRef
                , ctxPendingSendAction = sendActionRef
                , ctxCertRequests = crs
                , ctxKeyLogger = debugKeyLogger debug
                , ctxRecordLayer = recordLayer
                , ctxHandshakeSync = HandshakeSync syncNoOp syncNoOp
                , ctxQUICMode = False
                , ctxTLS13State = st13ref
                }

        syncNoOp _ _ = return ()

        recordLayer =
            RecordLayer
                { recordEncode12 = encodeRecord12
                , recordEncode13 = encodeRecord13
                , recordSendBytes = sendBytes
                , recordRecv12 = recvRecord12
                , recordRecv13 = recvRecord13
                }

    return ctx

contextHookSetHandshakeRecv :: Context -> (Handshake -> IO Handshake) -> IO ()
contextHookSetHandshakeRecv context f =
    contextModifyHooks context (\hooks -> hooks{hookRecvHandshake = f})

contextHookSetHandshake13Recv
    :: Context -> (Handshake13 -> IO Handshake13) -> IO ()
contextHookSetHandshake13Recv context f =
    contextModifyHooks context (\hooks -> hooks{hookRecvHandshake13 = f})

contextHookSetCertificateRecv :: Context -> (CertificateChain -> IO ()) -> IO ()
contextHookSetCertificateRecv context f =
    contextModifyHooks context (\hooks -> hooks{hookRecvCertificates = f})

contextHookSetLogging :: Context -> Logging -> IO ()
contextHookSetLogging context loggingCallbacks =
    contextModifyHooks context (\hooks -> hooks{hookLogging = loggingCallbacks})

{-# DEPRECATED getFinished "Use getTLSUnique instead" #-}

-- | Getting TLS Finished sent to peer.
getFinished :: Context -> IO (Maybe VerifyData)
getFinished ctx = usingState_ ctx getMyVerifyData

{-# DEPRECATED getPeerFinished "Use getTLSUnique instead" #-}

-- | Getting TLS Finished received from peer.
getPeerFinished :: Context -> IO (Maybe VerifyData)
getPeerFinished ctx = usingState_ ctx getPeerVerifyData

-- | Getting the "tls-unique" channel binding for TLS 1.2 (RFC5929).
--   For TLS 1.3, 'Nothing' is returned.
--   'supportedExtendedMainSecret' must be 'RequireEMS'
--   But in general, it is highly recommended to upgrade to TLS 1.3
--   and use the "tls-exporter" channel binding via 'getTLSExporter'.
getTLSUnique :: Context -> IO (Maybe ByteString)
getTLSUnique ctx = do
    ver <- liftIO $ usingState_ ctx getVersion
    if ver == TLS12
        then do
            mx <- usingState_ ctx getFirstVerifyData
            case mx of
                Nothing -> return Nothing
                Just (VerifyData verifyData) -> return $ Just verifyData
        else return Nothing

-- | Getting the "tls-exporter" channel binding for TLS 1.3 (RFC9266).
--   For TLS 1.2, 'Nothing' is returned.
getTLSExporter :: Context -> IO (Maybe ByteString)
getTLSExporter ctx = do
    ver <- liftIO $ usingState_ ctx getVersion
    if ver == TLS13
        then exporter ctx "EXPORTER-Channel-Binding" "" 32
        else return Nothing

exporter :: Context -> ByteString -> ByteString -> Int -> IO (Maybe ByteString)
exporter ctx label context outlen = do
    msecret <- usingState_ ctx getTLS13ExporterSecret
    mcipher <- failOnEitherError $ runRxRecordState ctx $ gets stCipher
    return $ case (msecret, mcipher) of
        (Just secret, Just cipher) ->
            let h = cipherHash cipher
                secret' = deriveSecret h secret label ""
                label' = "exporter"
                value' = hash h context
                key = hkdfExpandLabel h secret' label' value' outlen
             in Just key
        _ -> Nothing

-- | Getting the "tls-server-end-point" channel binding for TLS 1.2
--   (RFC5929).  For 1.3, there is no specifications for how to create
--   it.  In this implementation, a certificate chain without
--   extensions is hashed like TLS 1.2.
getTLSServerEndPoint :: Context -> IO (Maybe ByteString)
getTLSServerEndPoint ctx = do
    mcc <- usingState_ ctx getServerCertificateChain
    case mcc of
        Nothing -> return Nothing
        Just cc -> do
            (usedHash, _, _, _) <- getRxRecordState ctx
            return $ Just $ hash usedHash $ encodeCertificate cc
