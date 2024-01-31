{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.TLS.Context.Internal (
    -- * Context configuration
    ClientParams (..),
    ServerParams (..),
    defaultParamsClient,
    SessionID,
    SessionData (..),
    MaxFragmentEnum (..),
    Measurement (..),

    -- * Context object and accessor
    Context (..),
    Hooks (..),
    Established (..),
    PendingRecvAction (..),
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
    updateRecordLayer,
    updateMeasure,
    withMeasure,
    withReadLock,
    withWriteLock,
    withStateLock,
    withRWLock,

    -- * information
    Information (..),
    contextGetInformation,

    -- * Using context states
    throwCore,
    failOnEitherError,
    usingState,
    usingState_,
    runTxState,
    runRxState,
    usingHState,
    getHState,
    saveHState,
    restoreHState,
    getStateRNG,
    tls13orLater,
    addCertRequest13,
    getCertRequest13,
    decideRecordVersion,

    -- * Misc
    HandshakeSync (..),
    TLS13State (..),
    defaultTLS13State,
    getTLS13State,
    modifyTLS13State,
    CipherChoice (..),
    makeCipherChoice,
) where

import Control.Concurrent.MVar
import Control.Exception (throwIO)
import Control.Monad.State.Strict
import qualified Data.ByteString as B
import Data.IORef
import Data.Tuple

import Network.TLS.Backend
import Network.TLS.Cipher
import Network.TLS.Compression (Compression)
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Control
import Network.TLS.Handshake.State
import Network.TLS.Hooks
import Network.TLS.Imports
import Network.TLS.Measurement
import Network.TLS.Parameters
import Network.TLS.Record
import Network.TLS.Record.State
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types
import Network.TLS.Util

-- | Information related to a running context, e.g. current cipher
data Information = Information
    { infoVersion :: Version
    , infoCipher :: Cipher
    , infoCompression :: Compression
    , infoMainSecret :: Maybe ByteString
    , infoExtendedMainSecret :: Bool
    , infoClientRandom :: Maybe ClientRandom
    , infoServerRandom :: Maybe ServerRandom
    , infoSupportedGroup :: Maybe Group
    , infoTLS12Resumption :: Bool
    , infoTLS13HandshakeMode :: Maybe HandshakeMode13
    , infoIsEarlyDataAccepted :: Bool
    }
    deriving (Show, Eq)

-- | A TLS Context keep tls specific state, parameters and backend information.
data Context = forall a.
      Monoid a =>
    Context
    { ctxBackend :: Backend
    -- ^ return the backend object associated with this context
    , ctxSupported :: Supported
    , ctxShared :: Shared
    , ctxState :: MVar TLSState
    , ctxMeasurement :: IORef Measurement
    , ctxEOF_ :: IORef Bool
    -- ^ has the handle EOFed or not.
    , ctxEstablished_ :: IORef Established
    -- ^ has the handshake been done and been successful.
    , ctxNeedEmptyPacket :: IORef Bool
    -- ^ empty packet workaround for CBC guessability.
    , ctxFragmentSize :: Maybe Int
    -- ^ maximum size of plaintext fragments
    , ctxTxState :: MVar RecordState
    -- ^ current tx state
    , ctxRxState :: MVar RecordState
    -- ^ current rx state
    , ctxHandshake :: MVar (Maybe HandshakeState)
    -- ^ optional handshake state
    , ctxDoHandshake :: Context -> IO ()
    , ctxDoHandshakeWith :: Context -> Handshake -> IO ()
    , ctxDoRequestCertificate :: Context -> IO Bool
    , ctxDoPostHandshakeAuthWith :: Context -> Handshake13 -> IO ()
    , ctxHooks :: IORef Hooks
    -- ^ hooks for this context
    , ctxLockWrite :: MVar ()
    -- ^ lock to use for writing data (including updating the state)
    , ctxLockRead :: MVar ()
    -- ^ lock to use for reading data (including updating the state)
    , ctxLockState :: MVar ()
    -- ^ lock used during read/write when receiving and sending packet.
    -- it is usually nested in a write or read lock.
    , ctxPendingRecvActions :: IORef [PendingRecvAction]
    , ctxPendingSendAction :: IORef (Maybe (Context -> IO ()))
    , ctxCertRequests :: IORef [Handshake13]
    -- ^ pending PHA requests
    , ctxKeyLogger :: String -> IO ()
    , ctxRecordLayer :: RecordLayer a
    , ctxHandshakeSync :: HandshakeSync
    , ctxQUICMode :: Bool
    , ctxTLS13State :: IORef TLS13State
    }

data CipherChoice = CipherChoice
    { cVersion :: Version
    , cCipher :: Cipher
    , cHash :: Hash
    , cZero :: ByteString
    }

makeCipherChoice :: Version -> Cipher -> CipherChoice
makeCipherChoice ver cipher = CipherChoice ver cipher h zero
  where
    h = cipherHash cipher
    zero = B.replicate (hashDigestSize h) 0

data TLS13State = TLS13State
    { tls13stRecvNST :: Bool -- client
    , tls13stSentClientCert :: Bool -- client
    , tls13stRecvSF :: Bool -- client
    , tls13stSentCF :: Bool -- client
    , tls13stRecvCF :: Bool -- server
    , tls13stPendingRecvData :: Maybe ByteString -- client
    , tls13stPendingSentData :: [ByteString] -> [ByteString] -- client
    , tls13stRTT :: Millisecond
    , tls13st0RTTAccepted :: Bool -- client
    , tls13stClientExtensions :: [ExtensionRaw] -- client
    , tls13stChoice :: ~CipherChoice -- client
    , tls13stHsKey :: Maybe (SecretTriple HandshakeSecret) -- client
    , tls13stSession :: Session
    , tls13stSentExtensions :: [ExtensionID]
    }

defaultTLS13State :: TLS13State
defaultTLS13State =
    TLS13State
        { tls13stRecvNST = False
        , tls13stSentClientCert = False
        , tls13stRecvSF = False
        , tls13stSentCF = False
        , tls13stRecvCF = False
        , tls13stPendingRecvData = Nothing
        , tls13stPendingSentData = id
        , tls13stRTT = 0
        , tls13st0RTTAccepted = False
        , tls13stClientExtensions = []
        , tls13stChoice = undefined
        , tls13stHsKey = Nothing
        , tls13stSession = Session Nothing
        , tls13stSentExtensions = []
        }

getTLS13State :: Context -> IO TLS13State
getTLS13State Context{..} = readIORef ctxTLS13State

modifyTLS13State :: Context -> (TLS13State -> TLS13State) -> IO ()
modifyTLS13State Context{..} f = atomicModifyIORef' ctxTLS13State $ \st -> (f st, ())

data HandshakeSync
    = HandshakeSync
        (Context -> ClientState -> IO ())
        (Context -> ServerState -> IO ())

{- FOURMOLU_DISABLE -}
data RecordLayer a = RecordLayer
    { -- Writing.hs
      recordEncode    :: Context -> Record Plaintext -> IO (Either TLSError a)
    , recordEncode13  :: Context -> Record Plaintext -> IO (Either TLSError a)
    , recordSendBytes :: Context -> a -> IO ()
    , -- Reading.hs
      recordRecv      :: Context -> Int -> IO (Either TLSError (Record Plaintext))
    , recordRecv13    :: Context -> IO (Either TLSError (Record Plaintext))
    }
{- FOURMOLU_ENABLE -}

updateRecordLayer :: Monoid a => RecordLayer a -> Context -> Context
updateRecordLayer recordLayer Context{..} =
    Context{ctxRecordLayer = recordLayer, ..}

data Established
    = NotEstablished
    | EarlyDataAllowed Int -- server: remaining 0-RTT bytes allowed
    | EarlyDataNotAllowed Int -- sever: remaining 0-RTT packets allowed to skip
    | EarlyDataSending
    | Established
    deriving (Eq, Show)

data PendingRecvAction
    = -- | simple pending action. The first 'Bool' is necessity of alignment.
      PendingRecvAction Bool (Handshake13 -> IO ())
    | -- | pending action taking transcript hash up to preceding message
      --   The first 'Bool' is necessity of alignment.
      PendingRecvActionHash Bool (ByteString -> Handshake13 -> IO ())

updateMeasure :: Context -> (Measurement -> Measurement) -> IO ()
updateMeasure ctx = modifyIORef' (ctxMeasurement ctx)

withMeasure :: Context -> (Measurement -> IO a) -> IO a
withMeasure ctx f = readIORef (ctxMeasurement ctx) >>= f

-- | A shortcut for 'backendFlush . ctxBackend'.
contextFlush :: Context -> IO ()
contextFlush = backendFlush . ctxBackend

-- | A shortcut for 'backendClose . ctxBackend'.
contextClose :: Context -> IO ()
contextClose = backendClose . ctxBackend

-- | Information about the current context
contextGetInformation :: Context -> IO (Maybe Information)
contextGetInformation ctx = do
    ver <- usingState_ ctx $ gets stVersion
    hstate <- getHState ctx
    let (ms, ems, cr, sr, hm13, grp) =
            case hstate of
                Just st ->
                    ( hstMainSecret st
                    , hstExtendedMainSecret st
                    , Just (hstClientRandom st)
                    , hstServerRandom st
                    , if ver == Just TLS13 then Just (hstTLS13HandshakeMode st) else Nothing
                    , hstSupportedGroup st
                    )
                Nothing -> (Nothing, False, Nothing, Nothing, Nothing, Nothing)
    (cipher, comp) <-
        readMVar (ctxRxState ctx) <&> \st -> (stCipher st, stCompression st)
    let accepted = case hstate of
            Just st -> hstTLS13RTT0Status st == RTT0Accepted
            Nothing -> False
    tls12resumption <- usingState_ ctx isSessionResuming
    case (ver, cipher) of
        (Just v, Just c) ->
            return $
                Just $
                    Information v c comp ms ems cr sr grp tls12resumption hm13 accepted
        _ -> return Nothing

contextSend :: Context -> ByteString -> IO ()
contextSend c b =
    updateMeasure c (addBytesSent $ B.length b) >> (backendSend $ ctxBackend c) b

contextRecv :: Context -> Int -> IO ByteString
contextRecv c sz = updateMeasure c (addBytesReceived sz) >> (backendRecv $ ctxBackend c) sz

ctxEOF :: Context -> IO Bool
ctxEOF ctx = readIORef $ ctxEOF_ ctx

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

throwCore :: MonadIO m => TLSError -> m a
throwCore = liftIO . throwIO . Uncontextualized

failOnEitherError :: MonadIO m => m (Either TLSError a) -> m a
failOnEitherError f = do
    ret <- f
    case ret of
        Left err -> throwCore err
        Right r -> return r

usingState :: Context -> TLSSt a -> IO (Either TLSError a)
usingState ctx f =
    modifyMVar (ctxState ctx) $ \st ->
        let (a, newst) = runTLSState f st
         in newst `seq` return (newst, a)

usingState_ :: Context -> TLSSt a -> IO a
usingState_ ctx f = failOnEitherError $ usingState ctx f

usingHState :: MonadIO m => Context -> HandshakeM a -> m a
usingHState ctx f = liftIO $ modifyMVar (ctxHandshake ctx) $ \case
    Nothing -> liftIO $ throwIO MissingHandshake
    Just st -> return $ swap (Just <$> runHandshake st f)

getHState :: MonadIO m => Context -> m (Maybe HandshakeState)
getHState ctx = liftIO $ readMVar (ctxHandshake ctx)

saveHState :: Context -> IO (Saved (Maybe HandshakeState))
saveHState ctx = saveMVar (ctxHandshake ctx)

restoreHState
    :: Context
    -> Saved (Maybe HandshakeState)
    -> IO (Saved (Maybe HandshakeState))
restoreHState ctx = restoreMVar (ctxHandshake ctx)

decideRecordVersion :: Context -> IO (Version, Bool)
decideRecordVersion ctx = usingState_ ctx $ do
    ver <- getVersionWithDefault (maximum $ supportedVersions $ ctxSupported ctx)
    hrr <- getTLS13HRR
    -- For TLS 1.3, ver' is only used in ClientHello.
    -- The record version of the first ClientHello SHOULD be TLS 1.0.
    -- The record version of the second ClientHello MUST be TLS 1.2.
    let ver'
            | ver >= TLS13 = if hrr then TLS12 else TLS10
            | otherwise = ver
    return (ver', ver >= TLS13)

runTxState :: Context -> RecordM a -> IO (Either TLSError a)
runTxState ctx f = do
    (ver, tls13) <- decideRecordVersion ctx
    let opt =
            RecordOptions
                { recordVersion = ver
                , recordTLS13 = tls13
                }
    modifyMVar (ctxTxState ctx) $ \st ->
        case runRecordM f opt st of
            Left err -> return (st, Left err)
            Right (a, newSt) -> return (newSt, Right a)

runRxState :: Context -> RecordM a -> IO (Either TLSError a)
runRxState ctx f = do
    ver <-
        usingState_
            ctx
            (getVersionWithDefault $ maximum $ supportedVersions $ ctxSupported ctx)
    -- For 1.3, ver is just ignored. So, it is not necessary to convert ver.
    let opt =
            RecordOptions
                { recordVersion = ver
                , recordTLS13 = ver >= TLS13
                }
    modifyMVar (ctxRxState ctx) $ \st ->
        case runRecordM f opt st of
            Left err -> return (st, Left err)
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
    ev <- liftIO $ usingState ctx $ getVersionWithDefault TLS12
    return $ case ev of
        Left _ -> False
        Right v -> v >= TLS13

addCertRequest13 :: Context -> Handshake13 -> IO ()
addCertRequest13 ctx certReq = modifyIORef (ctxCertRequests ctx) (certReq :)

getCertRequest13 :: Context -> CertReqContext -> IO (Maybe Handshake13)
getCertRequest13 ctx context = do
    let ref = ctxCertRequests ctx
    l <- readIORef ref
    let (matched, others) = partition (\cr -> context == fromCertRequest13 cr) l
    case matched of
        [] -> return Nothing
        (certReq : _) -> writeIORef ref others >> return (Just certReq)
  where
    fromCertRequest13 (CertRequest13 c _) = c
    fromCertRequest13 _ = error "fromCertRequest13"
