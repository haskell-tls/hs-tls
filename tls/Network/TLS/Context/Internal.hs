{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE LambdaCase #-}
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
    Limit (..),
    Established (..),
    PendingRecv (..),
    PendingRecvAction (..),
    RecordLayer (..),
    Locks (..),
    GiveUp (..),
    GaveUp (..),
    gaveUpSending,
    withRxGiveUp,
    withTxGiveUp,
    RoleParams (..),
    ctxEOF,
    ctxCloseNotify,
    ctxTxBroken,
    ctxTxBrokenBy,
    ctxRxBrokenBy,
    ctxEstablished,
    withLog,
    ctxWithHooks,
    contextModifyHooks,
    setEOF,
    setCloseNotify,
    setTxBroken,
    setRxBroken,
    wakePHA,
    throwBroken,
    setEstablished,
    skipEarlyData,
    contextFlush,
    contextClose,
    contextSend,
    contextRecv,
    updateRecordLayer,
    updateMeasure,
    withMeasure,
    withReadLock,
    withReadLockGivingUp,
    tryWithReadLock,
    withWriteLock,
    myRxGiveUp,
    withWriteLockGivingUp,
    withStateLock,
    withRWLock,
    withRWLockGivingUp,

    -- * information
    Information (..),
    contextGetInformation,

    -- * Using context states
    throwCore,
    failOnEitherError,
    usingState,
    usingState_,
    runTxRecordState,
    runRxRecordState,
    usingHState,
    getHState,
    saveHState,
    restoreHState,
    getStateRNG,
    tls13orLater,
    decideRecordVersion,

    -- * Misc
    HandshakeSync (..),
    PHAResult (..),
    TLS13State (..),
    defaultTLS13State,
    getTLS13State,
    modifyTLS13State,
    incrementTLS13KeyUpdateCount,
    resetTLS13KeyUpdateCount,
    CipherChoice (..),
    makeCipherChoice,

    -- * RecordLimit
    setMyRecordLimit,
    enableMyRecordLimit,
    getMyRecordLimit,
    checkMyRecordLimit,
    setPeerRecordLimit,
    enablePeerRecordLimit,
    getPeerRecordLimit,
    checkPeerRecordLimit,
    newRecordLimitRef,

    -- * ECH
    HPKEF,
    getTLS13HPKE,
    setTLS13HPKE,
) where

import Control.Concurrent (ThreadId, myThreadId)
import Control.Concurrent.MVar
import Control.Concurrent.STM
import qualified Control.Exception as E
import Control.Monad.State.Strict
import Data.ByteArray (convert)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import Data.IORef
import Data.Tuple

import Network.TLS.Backend
import Network.TLS.Cipher
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
import Network.TLS.X509 (CertificateChain)

-- | A TLS Context keeps TLS specific state, parameters and backend information.
data Context
    = forall a.
      Monoid a =>
    Context
    { ctxBackend :: Backend
    -- ^ return the backend object associated with this context
    , ctxBackendRecvWith :: Maybe RecvWith
    -- ^ 'getBackendRecvWith' of the backend
    , ctxBackendSendWith :: Maybe SendWith
    -- ^ 'getBackendSendWith' of the backend
    , ctxRxGiveUp :: IORef (Maybe (ThreadId, GiveUp))
    -- ^ what a receive through 'ctxBackendRecvWith' gives up on, set
    -- with the read lock taken, and the thread which set it
    , ctxTxGiveUp :: IORef (Maybe (STM ()))
    -- ^ what a send through 'ctxBackendSendWith' gives up on, set with
    -- the write lock taken
    , ctxSupported :: Supported
    , ctxShared :: Shared
    , ctxDebug :: DebugParams
    , ctxTLSState :: MVar TLSState
    , ctxMeasurement :: IORef Measurement
    , ctxEOF_ :: IORef Bool
    -- ^ has the handle EOFed or not.
    , ctxCloseNotify_ :: IORef Bool
    -- ^ has close_notify been received or not.
    , ctxTxBroken_ :: IORef (Maybe E.SomeException)
    -- ^ the exception of the first failed send, which left the TX record
    -- state ahead of the peer.
    , ctxRxBroken_ :: IORef (Maybe E.SomeException)
    -- ^ the exception which interrupted a receive inside a record.
    , ctxEstablished_ :: IORef Established
    -- ^ has the handshake been done and been successful.
    , ctxTxRecordState :: MVar RecordState
    -- ^ current TX record state
    , ctxRxRecordState :: MVar RecordState
    -- ^ current RX record state
    , ctxHandshakeState :: MVar (Maybe HandshakeState)
    -- ^ optional handshake state
    , ctxRoleParams :: RoleParams
    -- ^ hooks for this context
    , ctxLocks :: Locks
    , ctxHooks :: IORef Hooks
    , -- TLS 1.3
      ctxTLS13State :: IORef TLS13State
    , ctxPendingRecvActions :: IORef [PendingRecvAction]
    , ctxPendingAppData :: IORef [ByteString]
    -- ^ TLS 1.2 application data received during renegotiation, newest first
    , ctxPendingSendAction :: IORef (Maybe (Context -> IO ()))
    -- ^ pending post handshake authentication requests
    , -- QUIC
      ctxRecordLayer :: RecordLayer a
    , ctxHandshakeSync :: HandshakeSync
    , ctxQUICMode :: Bool
    , -- Misc
      ctxNeedEmptyPacket :: IORef Bool
    -- ^ empty packet workaround for CBC guessability.
    , ctxMyRecordLimit :: IORef RecordLimit
    -- ^ maximum size of plaintext fragments, val + 1 is used for TLS 1.3
    , ctxPeerRecordLimit :: IORef RecordLimit
    -- ^ maximum size of plaintext fragments, val + 1 is used for TLS 1.3
    , ctxHPKE :: IORef (Maybe (HPKEF, Int))
    }

type HPKEF = ByteString -> ByteString -> IO ByteString

data RecordLimit
    = NoRecordLimit -- for QUIC
    | RecordLimit
        Int -- effective
        (Maybe Int) -- pending
    deriving (Eq, Show)

data RoleParams = RoleParams
    { doHandshake_ :: Context -> IO ()
    , doHandshakeWith_ :: Context -> HandshakeR -> IO ()
    , doRequestCertificate_ :: Context -> IO Bool
    , doRequestCertificateAsync_ :: Context -> IO (Bool -> IO PHAResult)
    , doPostHandshakeAuthWith_ :: Context -> Handshake13R -> IO ()
    }

-- | What a receive gives up on: before the first byte of a record, and
-- inside a record, which leaves the stream there.
data GiveUp = GiveUp
    { giveUpBetween :: STM ()
    , giveUpInside :: STM ()
    }

-- | Thrown by a receive which has given up before the first byte of a
-- record, and caught by the caller which set 'ctxRxGiveUp'.
data GaveUp = GaveUp deriving (Show)

instance E.Exception GaveUp

-- | Thrown by a send which has given up, which may have sent part of a
-- record.
gaveUpSending :: TLSException
gaveUpSending = PostHandshake $ Error_Misc "gave up sending"

-- | Running with a give-up for the receives; the read lock is taken.
withRxGiveUp :: Context -> GiveUp -> IO a -> IO a
withRxGiveUp ctx g f = do
    tid <- myThreadId
    withGiveUpIn (ctxRxGiveUp ctx) (tid, g) f

-- | Running with a give-up for the sends; the write lock is taken.
withTxGiveUp :: Context -> STM () -> IO a -> IO a
withTxGiveUp ctx = withGiveUpIn (ctxTxGiveUp ctx)

withGiveUpIn :: IORef (Maybe b) -> b -> IO a -> IO a
withGiveUpIn ref g f =
    E.bracket
        (atomicModifyIORef' ref (\old -> (Just g, old)))
        (writeIORef ref)
        (const f)

-- | 'TMVar's, so that a wait for them can be given up on.
data Locks = Locks
    { lockWrite :: TMVar ()
    -- ^ lock to use for writing data (including updating the state)
    , lockRead :: TMVar ()
    -- ^ lock to use for reading data (including updating the state)
    , lockState :: TMVar ()
    -- ^ lock used during read/write when receiving and sending packet.
    -- it is usually nested in a write or read lock.
    }

data CipherChoice = CipherChoice
    { cVersion :: Version
    , cCipher :: Cipher
    , cHash :: Hash
    , cZero :: Secret
    }
    deriving (Show)

makeCipherChoice :: Version -> Cipher -> CipherChoice
makeCipherChoice ver cipher = CipherChoice ver cipher h zero
  where
    h = cipherHash cipher
    zero = BA.replicate (hashDigestSize h) 0

data TLS13State = TLS13State
    { tls13stRecvNST :: Bool -- client
    , tls13stKeyUpdateCount :: Int
    , tls13stSentKeyUpdates :: Word64
    , tls13stKeyUpdateResponded :: Bool
    , tls13stSentClientCert :: Bool -- client
    , tls13stRecvSF :: Bool -- client
    , tls13stSentCF :: Bool -- client
    , tls13stRecvCF :: Bool -- server
    , tls13stPendingRecv :: PendingRecv -- client
    , tls13stPendingSentData :: [ByteString] -> [ByteString] -- client
    , tls13stRTT :: Millisecond
    , tls13st0RTT :: Bool -- client
    , tls13st0RTTAccepted :: Bool -- client
    , tls13stClientExtensions :: [ExtensionRaw] -- client
    , tls13stChoice :: ~CipherChoice -- client
    , tls13stHsKey :: Maybe (SecretTriple HandshakeSecret) -- client
    -- Actual session id for TLS 1.2, random value for TLS 1.3
    , tls13stSession :: Session
    , tls13stSentExtensions :: [ExtensionID]
    , tls13stPHA :: Maybe (MVar PHAResult, TLSError)
    -- ^ server: the result of the pending post-handshake authentication,
    -- and the error given to the waiters when the connection is closed
    , tls13stPHAResponding :: Bool
    -- ^ server: the client's response has begun, so nothing else may come
    -- until its Finished
    }

-- | The result of 'Network.TLS.requestCertificateAsync'.
data PHAResult
    = -- | The request could not be sent: TLS 1.2, no post_handshake_auth
      -- from the client, or another request pending.
      PHAUnavailable
    | -- | No response yet.  Only when not waiting.
      PHAPending
    | -- | The client was authenticated with this chain.
      PHAAccepted CertificateChain
    | -- | The client sent an empty certificate, accepted by
      -- @onClientCertificate@.
      PHADeclined
    | -- | The verification failed or the connection was closed.
      PHAFailed TLSError
    deriving (Eq, Show)

defaultTLS13State :: TLS13State
defaultTLS13State =
    TLS13State
        { tls13stRecvNST = False
        , tls13stKeyUpdateCount = 0
        , tls13stSentKeyUpdates = 0
        , tls13stKeyUpdateResponded = False
        , tls13stSentClientCert = False
        , tls13stRecvSF = False
        , tls13stSentCF = False
        , tls13stRecvCF = False
        , tls13stPendingRecv = NoPendingRecv
        , tls13stPendingSentData = id
        , tls13stRTT = 0
        , tls13st0RTT = False
        , tls13st0RTTAccepted = False
        , tls13stClientExtensions = []
        , tls13stChoice = undefined
        , tls13stHsKey = Nothing
        , tls13stSession = Session Nothing
        , tls13stSentExtensions = []
        , tls13stPHA = Nothing
        , tls13stPHAResponding = False
        }

getTLS13State :: Context -> IO TLS13State
getTLS13State Context{..} = readIORef ctxTLS13State

modifyTLS13State :: Context -> (TLS13State -> TLS13State) -> IO ()
modifyTLS13State Context{..} f = atomicModifyIORef' ctxTLS13State $ \st -> (f st, ())

incrementTLS13KeyUpdateCount :: Context -> IO Int
incrementTLS13KeyUpdateCount Context{..} =
    atomicModifyIORef' ctxTLS13State $ \st ->
        let count = tls13stKeyUpdateCount st + 1
         in (st{tls13stKeyUpdateCount = count}, count)

resetTLS13KeyUpdateCount :: Context -> IO ()
resetTLS13KeyUpdateCount ctx =
    modifyTLS13State ctx $ \st -> st{tls13stKeyUpdateCount = 0}

data HandshakeSync
    = HandshakeSync
        (Context -> ClientState -> IO ())
        (Context -> ServerState -> IO ())

{- FOURMOLU_DISABLE -}
data RecordLayer a = RecordLayer
    { -- Writing.hs
      recordEncode12  :: Context -> Record Plaintext -> IO (Either TLSError a)
    , recordEncode13  :: Context -> Record Plaintext -> IO (Either TLSError a)
    , recordSendBytes :: Context -> a -> IO ()
    , -- Reading.hs
      recordRecv12    :: Context -> IO (Either TLSError (Record Plaintext))
    , recordRecv13    :: Context -> IO (Either TLSError (Record Plaintext))
    }
{- FOURMOLU_ENABLE -}

updateRecordLayer :: Monoid a => RecordLayer a -> Context -> Context
updateRecordLayer recordLayer Context{..} =
    Context{ctxRecordLayer = recordLayer, ..}

data Established
    = NotEstablished
    | EarlyDataAllowed Word32 -- server: remaining 0-RTT bytes allowed
    | EarlyDataNotAllowed Word32 -- server: remaining 0-RTT bytes allowed to skip
    | EarlyDataSending
    | Established
    deriving (Eq, Show)

-- | Outcome of a read that was started on behalf of a caller who is no longer
-- waiting for it, held until the next receive hands it over.  Reads cannot be
-- abandoned once started -- see 'Network.TLS.Core.handshake' -- so a reader that
-- outlives its caller leaves its result here instead.
data PendingRecv
    = NoPendingRecv
    | PendingRecvData ByteString
    | PendingRecvError E.SomeException

data PendingRecvAction
    = -- | simple pending action. The first 'Bool' is necessity of alignment.
      PendingRecvAction Bool (Handshake13 -> IO ())
    | PendingRecvActionSelfUpdate Bool (Handshake13R -> IO ())
    | -- | pending action taking transcript hash up to preceding message
      --   The first 'Bool' is necessity of alignment.
      PendingRecvActionHash
        Bool
        (TranscriptHash -> Handshake13 -> IO ())

updateMeasure :: Context -> (Measurement -> Measurement) -> IO ()
updateMeasure ctx = modifyIORef' (ctxMeasurement ctx)

withMeasure :: Context -> (Measurement -> IO a) -> IO a
withMeasure ctx f = readIORef (ctxMeasurement ctx) >>= f

-- | A shortcut for 'backendFlush . ctxBackend'.
contextFlush :: Context -> IO ()
contextFlush = backendFlush . ctxBackend

-- | A shortcut for 'backendClose . ctxBackend'.
--
--   For a 'Network.Socket.Socket', this is 'Network.Socket.close', which
--   also wakes up threads blocked on the socket.  If no thread is left on
--   it, call 'Network.TLS.bye' and then @unsafeClose@ (network 3.2.11 or
--   later) on the socket instead, or give 'Network.TLS.contextNew' a
--   'Backend' whose 'backendClose' does so.
contextClose :: Context -> IO ()
contextClose = backendClose . ctxBackend

-- | Information about the current context
contextGetInformation :: Context -> IO (Maybe Information)
contextGetInformation ctx = do
    ver <- usingState_ ctx $ gets stVersion
    hstate <- getHState ctx
    let (ms, ems, cr, sr, hm13, grp, ech, ssig, csig) =
            case hstate of
                Just st ->
                    ( hstMainSecret st
                    , hstExtendedMainSecret st
                    , Just (hstClientRandom st)
                    , hstServerRandom st
                    , if ver == Just TLS13 then Just (hstTLS13HandshakeMode st) else Nothing
                    , hstSupportedGroup st
                    , hstTLS13ECHAccepted st
                    , hstServerSignatureScheme st
                    , hstClientSignatureScheme st
                    )
                Nothing ->
                    (Nothing, False, Nothing, Nothing, Nothing, Nothing, False, Nothing, Nothing)
    (cipher, comp) <-
        readMVar (ctxRxRecordState ctx) <&> \st -> (stCipher st, stCompression st)
    let accepted = case hstate of
            Just st -> hstTLS13RTT0Status st == RTT0Accepted
            Nothing -> False
    tls12resumption <- usingState_ ctx getTLS12SessionResuming
    case (ver, cipher) of
        (Just v, Just c) ->
            return $
                Just $
                    Information
                        { infoVersion = v
                        , infoCipher = c
                        , infoCompression = comp
                        , infoMainSecret = convert <$> ms
                        , infoExtendedMainSecret = ems
                        , infoClientRandom = cr
                        , infoServerRandom = sr
                        , infoSupportedGroup = grp
                        , infoTLS12Resumption = tls12resumption
                        , infoTLS13HandshakeMode = hm13
                        , infoIsEarlyDataAccepted = accepted
                        , infoIsECHAccepted = ech
                        , infoServerSignatureScheme = ssig
                        , infoClientSignatureScheme = csig
                        }
        _ -> return Nothing

contextSend :: Context -> ByteString -> IO ()
contextSend c b = do
    updateMeasure c (addBytesSent $ B.length b)
    mgiveUp <- readIORef $ ctxTxGiveUp c
    case (mgiveUp, ctxBackendSendWith c) of
        (Just giveUp, Just (SendWith sendWith)) ->
            sendWith b giveUp >>= either (\_ -> E.throwIO gaveUpSending) return
        _ -> backendSend (ctxBackend c) b

contextRecv :: Context -> Int -> IO ByteString
contextRecv c sz = updateMeasure c (addBytesReceived sz) >> (backendRecv $ ctxBackend c) sz

ctxEOF :: Context -> IO Bool
ctxEOF ctx = readIORef $ ctxEOF_ ctx

setEOF :: Context -> IO ()
setEOF ctx = do
    writeIORef (ctxEOF_ ctx) True
    wakePHA ctx

-- | Wake up those waiting for a pending post-handshake authentication.
wakePHA :: Context -> IO ()
wakePHA ctx = do
    mpha <- tls13stPHA <$> readIORef (ctxTLS13State ctx)
    forM_ mpha $ \(mv, err) -> void $ tryPutMVar mv $ PHAFailed err

ctxCloseNotify :: Context -> IO Bool
ctxCloseNotify ctx = readIORef $ ctxCloseNotify_ ctx

setCloseNotify :: Context -> IO ()
setCloseNotify ctx = writeIORef (ctxCloseNotify_ ctx) True

ctxTxBroken :: Context -> IO Bool
ctxTxBroken ctx = isJust <$> ctxTxBrokenBy ctx

ctxTxBrokenBy :: Context -> IO (Maybe E.SomeException)
ctxTxBrokenBy ctx = readIORef $ ctxTxBroken_ ctx

setTxBroken :: Context -> E.SomeException -> IO ()
setTxBroken ctx e = atomicModifyIORef' (ctxTxBroken_ ctx) $ \m -> (m <|> Just e, ())

ctxRxBrokenBy :: Context -> IO (Maybe E.SomeException)
ctxRxBrokenBy ctx = readIORef $ ctxRxBroken_ ctx

-- | Throw again the exception which broke a direction.  An asynchronous
-- one was meant for the thread which got it, so it is replaced.
throwBroken :: String -> E.SomeException -> IO a
throwBroken msg e = E.throwIO $ case E.fromException e of
    Just (E.SomeAsyncException _) -> E.toException $ PostHandshake $ Error_Misc msg
    Nothing -> e

-- | The stream is left inside a record, so nothing more can be received.
setRxBroken :: Context -> E.SomeException -> IO ()
setRxBroken ctx e = do
    atomicModifyIORef' (ctxRxBroken_ ctx) $ \m -> (m <|> Just e, ())
    wakePHA ctx

ctxEstablished :: Context -> IO Established
ctxEstablished ctx = readIORef $ ctxEstablished_ ctx

ctxWithHooks :: Context -> (Hooks -> IO a) -> IO a
ctxWithHooks ctx f = readIORef (ctxHooks ctx) >>= f

contextModifyHooks :: Context -> (Hooks -> Hooks) -> IO ()
contextModifyHooks ctx = modifyIORef' (ctxHooks ctx)

setEstablished :: Context -> Established -> IO ()
setEstablished ctx = writeIORef (ctxEstablished_ ctx)

-- | Skips a record of rejected early data, given its length on the wire, if
-- the server is skipping them.  Going over what may be skipped is refused
-- with unexpected_message (RFC 9846 Section 4.2.10).
skipEarlyData :: Context -> Int -> IO Bool
skipEarlyData ctx len = do
    established <- ctxEstablished ctx
    case established of
        EarlyDataNotAllowed n
            | cost <= n -> do
                setEstablished ctx $ EarlyDataNotAllowed (n - cost)
                return True
            | otherwise ->
                throwCore $ Error_Protocol "too much early data to skip" UnexpectedMessage
        _ -> return False
  where
    -- The AEAD tag and the inner content type are not early data.
    cost = fromIntegral $ max 1 (len - 17)

withLog :: Context -> (Logging -> IO ()) -> IO ()
withLog ctx f = ctxWithHooks ctx (f . hookLogging)

throwCore :: MonadIO m => TLSError -> m a
throwCore = liftIO . E.throwIO . Uncontextualized

failOnEitherError :: MonadIO m => m (Either TLSError a) -> m a
failOnEitherError f = do
    ret <- f
    case ret of
        Left err -> throwCore err
        Right r -> return r

usingState :: Context -> TLSSt a -> IO (Either TLSError a)
usingState ctx f =
    modifyMVar (ctxTLSState ctx) $ \st ->
        let (a, newst) = runTLSState f st
         in newst `seq` return (newst, a)

usingState_ :: Context -> TLSSt a -> IO a
usingState_ ctx f = failOnEitherError $ usingState ctx f

usingHState :: MonadIO m => Context -> HandshakeM a -> m a
usingHState ctx f = liftIO $ modifyMVar (ctxHandshakeState ctx) $ \case
    Nothing -> liftIO $ E.throwIO MissingHandshake
    Just st -> return $ swap (Just <$> runHandshake st f)

getHState :: MonadIO m => Context -> m (Maybe HandshakeState)
getHState ctx = liftIO $ readMVar (ctxHandshakeState ctx)

saveHState :: Context -> IO (Saved (Maybe HandshakeState))
saveHState ctx = saveMVar (ctxHandshakeState ctx)

restoreHState
    :: Context
    -> Saved (Maybe HandshakeState)
    -> IO (Saved (Maybe HandshakeState))
restoreHState ctx = restoreMVar (ctxHandshakeState ctx)

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

runTxRecordState :: Context -> RecordM a -> IO (Either TLSError a)
runTxRecordState ctx f = do
    (ver, tls13) <- decideRecordVersion ctx
    let opt =
            RecordOptions
                { recordVersion = ver
                , recordTLS13 = tls13
                }
    modifyMVar (ctxTxRecordState ctx) $ \st ->
        case runRecordM f opt st of
            Left err -> return (st, Left err)
            Right (a, newSt) -> return (newSt, Right a)

runRxRecordState :: Context -> RecordM a -> IO (Either TLSError a)
runRxRecordState ctx f = do
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
    modifyMVar (ctxRxRecordState ctx) $ \st ->
        case runRecordM f opt st of
            Left err -> return (st, Left err)
            Right (a, newSt) -> return (newSt, Right a)

getStateRNG :: Context -> Int -> IO ByteString
getStateRNG ctx n = usingState_ ctx $ genRandom n

withLock :: TMVar () -> IO a -> IO a
withLock lock = E.bracket_ (atomically $ takeTMVar lock) (atomically $ putTMVar lock ())

-- | Taking the lock unless the 'STM' action succeeds first.
withLockGivingUp :: TMVar () -> STM g -> IO a -> IO (Either g a)
withLockGivingUp lock giveUp f = E.mask $ \restore -> do
    r <- atomically $ (Right <$> takeTMVar lock) `orElse` (Left <$> giveUp)
    case r of
        Left g -> return $ Left g
        Right () -> (Right <$> restore f) `E.finally` atomically (putTMVar lock ())

withReadLock :: Context -> IO a -> IO a
withReadLock ctx = withLock (lockRead $ ctxLocks ctx)

withReadLockGivingUp :: Context -> STM g -> IO a -> IO (Either g a)
withReadLockGivingUp ctx = withLockGivingUp (lockRead $ ctxLocks ctx)

-- | Like 'withReadLock', but returns 'Nothing' immediately instead of waiting
-- when another thread already holds the read lock.
--
-- The read lock is what keeps a single thread reading the connection at a time.
-- Records arrive length-prefixed, so two threads reading in parallel would each
-- take a piece of whatever record the other was in the middle of, and neither
-- would end up with a usable message.
--
-- Use this instead of 'withReadLock' when the read is optional and skipping it
-- is better than waiting for the current reader, which may hold the lock for
-- arbitrarily long.  'bye' is the only such caller; see the note there.
tryWithReadLock :: Context -> IO a -> IO (Maybe a)
tryWithReadLock ctx f = either (const Nothing) Just <$> withReadLockGivingUp ctx (return ()) f

-- | Within a receive which gives up ('withRxGiveUp'), a send the receive
-- makes, such as a response to KeyUpdate or an alert, gives up with it,
-- also while waiting for the lock.  Neither side can then be used.
withWriteLock :: Context -> IO a -> IO a
withWriteLock ctx f = do
    tid <- myThreadId
    mgiveUp <- readIORef $ ctxRxGiveUp ctx
    case mgiveUp of
        Just (owner, GiveUp{giveUpInside = g})
            | owner == tid ->
                withWriteLockGivingUp ctx g (withTxGiveUp ctx g f)
                    >>= either (\_ -> gaveUp) return
        _ -> withLock (lockWrite $ ctxLocks ctx) f
  where
    gaveUp = do
        let e = E.toException gaveUpSending
        setTxBroken ctx e
        setRxBroken ctx e
        E.throwIO gaveUpSending

-- | The give-up of the receive which this thread is in, if any.
myRxGiveUp :: Context -> IO (STM ())
myRxGiveUp ctx = do
    tid <- myThreadId
    mgiveUp <- readIORef $ ctxRxGiveUp ctx
    return $ case mgiveUp of
        Just (owner, GiveUp{giveUpInside = g}) | owner == tid -> g
        _ -> retry

withWriteLockGivingUp :: Context -> STM g -> IO a -> IO (Either g a)
withWriteLockGivingUp ctx = withLockGivingUp (lockWrite $ ctxLocks ctx)

withRWLock :: Context -> IO a -> IO a
withRWLock ctx f = withReadLock ctx $ withWriteLock ctx f

withRWLockGivingUp :: Context -> STM g -> IO a -> IO (Either g a)
withRWLockGivingUp ctx giveUp f =
    join <$> withReadLockGivingUp ctx giveUp (withWriteLockGivingUp ctx giveUp f)

withStateLock :: Context -> IO a -> IO a
withStateLock ctx = withLock (lockState $ ctxLocks ctx)

tls13orLater :: MonadIO m => Context -> m Bool
tls13orLater ctx = do
    ev <- liftIO $ usingState ctx $ getVersionWithDefault TLS12
    return $ case ev of
        Left _ -> False
        Right v -> v >= TLS13

--------------------------------

setMyRecordLimit :: Context -> Maybe Int -> IO ()
setMyRecordLimit ctx msiz = modifyIORef' (ctxMyRecordLimit ctx) change
  where
    change (RecordLimit n _) = RecordLimit n msiz
    change x = x

enableMyRecordLimit :: Context -> IO ()
enableMyRecordLimit ctx = modifyIORef' (ctxMyRecordLimit ctx) change
  where
    change (RecordLimit _ (Just n)) = RecordLimit n Nothing
    change x = x

getMyRecordLimit :: Context -> IO (Maybe Int)
getMyRecordLimit ctx = change <$> readIORef (ctxMyRecordLimit ctx)
  where
    change NoRecordLimit = Nothing
    change (RecordLimit n _) = Just n

checkMyRecordLimit :: Context -> IO Bool
checkMyRecordLimit ctx = chk <$> readIORef (ctxMyRecordLimit ctx)
  where
    chk NoRecordLimit = False
    chk (RecordLimit _ mx) = isJust mx

--------------------------------

setPeerRecordLimit :: Context -> Maybe Int -> IO ()
setPeerRecordLimit ctx msiz = modifyIORef' (ctxPeerRecordLimit ctx) change
  where
    change (RecordLimit n _) = RecordLimit n msiz
    change x = x

enablePeerRecordLimit :: Context -> IO ()
enablePeerRecordLimit ctx = modifyIORef' (ctxPeerRecordLimit ctx) change
  where
    change (RecordLimit _ (Just n)) = RecordLimit n Nothing
    change x = x

getPeerRecordLimit :: Context -> IO (Maybe Int)
getPeerRecordLimit ctx = change <$> readIORef (ctxPeerRecordLimit ctx)
  where
    change NoRecordLimit = Nothing
    change (RecordLimit n _) = Just n

checkPeerRecordLimit :: Context -> IO Bool
checkPeerRecordLimit ctx = chk <$> readIORef (ctxPeerRecordLimit ctx)
  where
    chk NoRecordLimit = False
    chk (RecordLimit _ mx) = isJust mx

newRecordLimitRef :: Maybe Int -> IO (IORef RecordLimit)
newRecordLimitRef Nothing = newIORef NoRecordLimit
newRecordLimitRef (Just n) = newIORef $ RecordLimit n Nothing

--------------------------------

setTLS13HPKE :: Context -> HPKEF -> Int -> IO ()
setTLS13HPKE ctx func nenc = writeIORef (ctxHPKE ctx) $ Just (func, nenc)

getTLS13HPKE :: Context -> IO (Maybe (HPKEF, Int))
getTLS13HPKE ctx = readIORef $ ctxHPKE ctx
