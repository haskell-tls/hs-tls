module Run (
    checkCtxFinished,
    recvDataAssert,
    byeBye,
    runTLSPipe,
    runTLSPipeSimple,
    runTLSPipeSimple13,
    runTLSPipeSimpleKeyUpdate,
    runTLSPipePredicate,
    runTLSInitFailure,
    readClientSessionRef,
    twoSessionRefs,
    twoSessionManagers,
    setPairParamsSessionManagers,
    setPairParamsSessionResuming,
) where

import Control.Concurrent
import Control.Concurrent.Async
import qualified Control.Exception as E
import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Default.Class
import Data.Either
import Data.IORef
import Data.Maybe
import Network.TLS
import System.Timeout
import Test.Hspec
import Test.QuickCheck

import Arbitrary
import PipeChan

checkCtxFinished :: Context -> IO ()
checkCtxFinished ctx = do
    ctxFinished <- getFinished ctx
    unless (isJust ctxFinished) $
        fail "unexpected ctxFinished"
    ctxPeerFinished <- getPeerFinished ctx
    unless (isJust ctxPeerFinished) $
        fail "unexpected ctxPeerFinished"

recvDataAssert :: Context -> ByteString -> IO ()
recvDataAssert ctx expected = do
    got <- recvData ctx
    expected `shouldBe` got

runTLSPipeN
    :: Int
    -> (ClientParams, ServerParams)
    -> (Context -> Chan [ByteString] -> IO ())
    -> (Chan ByteString -> Context -> IO ())
    -> IO ()
runTLSPipeN n params tlsServer tlsClient = do
    -- generate some data to send
    ds <- replicateM n $ do
        d <- B.pack <$> generate (someWords8 256)
        return d
    -- send it
    m_dsres <- do
        withDataPipe params tlsServer tlsClient $ \(writeStart, readResult) -> do
            forM_ ds $ \d -> do
                writeStart d
            -- receive it
            timeout 60000000 readResult -- 60 sec
    case m_dsres of
        Nothing -> error "timed out"
        Just dsres -> ds `shouldBe` dsres

runTLSPipe
    :: (ClientParams, ServerParams)
    -> (Context -> Chan [ByteString] -> IO ())
    -> (Chan ByteString -> Context -> IO ())
    -> IO ()
runTLSPipe = runTLSPipeN 1

withDataPipe
    :: (ClientParams, ServerParams)
    -> (Context -> Chan result -> IO ())
    -> (Chan start -> Context -> IO ())
    -> ((start -> IO (), IO result) -> IO a)
    -> IO a
withDataPipe params tlsServer tlsClient cont = do
    -- initial setup
    pipe <- newPipe
    _ <- runPipe pipe
    startQueue <- newChan
    resultQueue <- newChan

    (cCtx, sCtx) <- newPairContext pipe params

    withAsync
        ( E.catch
            (tlsServer sCtx resultQueue)
            (printAndRaise "server" (serverSupported $ snd params))
        )
        $ \sAsync -> withAsync
            ( E.catch
                (tlsClient startQueue cCtx)
                (printAndRaise "client" (clientSupported $ fst params))
            )
            $ \cAsync -> do
                let readResult = waitBoth cAsync sAsync >> readChan resultQueue
                cont (writeChan startQueue, readResult)
  where
    printAndRaise :: String -> Supported -> E.SomeException -> IO ()
    printAndRaise s supported e = do
        putStrLn $
            s
                ++ " exception: "
                ++ show e
                ++ ", supported: "
                ++ show supported
        E.throwIO e

initiateDataPipe
    :: (ClientParams, ServerParams)
    -> (Context -> IO a1)
    -> (Context -> IO a)
    -> IO (Either E.SomeException a, Either E.SomeException a1)
initiateDataPipe params tlsServer tlsClient = do
    -- initial setup
    pipe <- newPipe
    _ <- runPipe pipe

    (cCtx, sCtx) <- newPairContext pipe params

    async (tlsServer sCtx) >>= \sAsync ->
        async (tlsClient cCtx) >>= \cAsync -> do
            sRes <- waitCatch sAsync
            cRes <- waitCatch cAsync
            return (cRes, sRes)

debug :: Bool
debug = False

newPairContext
    :: PipeChan -> (ClientParams, ServerParams) -> IO (Context, Context)
newPairContext pipe (cParams, sParams) = do
    let noFlush = return ()
    let noClose = return ()

    let cBackend = Backend noFlush noClose (writePipeA pipe) (readPipeA pipe)
    let sBackend = Backend noFlush noClose (writePipeB pipe) (readPipeB pipe)
    cCtx' <- contextNew cBackend cParams
    sCtx' <- contextNew sBackend sParams

    contextHookSetLogging cCtx' (logging "client: ")
    contextHookSetLogging sCtx' (logging "server: ")

    return (cCtx', sCtx')
  where
    logging pre =
        if debug
            then
                def
                    { loggingPacketSent = putStrLn . ((pre ++ ">> ") ++)
                    , loggingPacketRecv = putStrLn . ((pre ++ "<< ") ++)
                    }
            else def

-- Terminate the write direction and wait to receive the peer EOF.  This is
-- necessary in situations where we want to confirm the peer status, or to make
-- sure to receive late messages like session tickets.  In the test suite this
-- is used each time application code ends the connection without prior call to
-- 'recvData'.
byeBye :: Context -> IO ()
byeBye ctx = do
    bye ctx
    bs <- recvData ctx
    unless (B.null bs) $ fail "byeBye: unexpected application data"

runTLSPipePredicate
    :: (ClientParams, ServerParams) -> (Maybe Information -> Bool) -> IO ()
runTLSPipePredicate params p = runTLSPipe params tlsServer tlsClient
  where
    tlsServer ctx queue = do
        handshake ctx
        checkCtxFinished ctx
        checkInfoPredicate ctx
        d <- recvData ctx
        writeChan queue [d]
        bye ctx
    tlsClient queue ctx = do
        handshake ctx
        checkCtxFinished ctx
        checkInfoPredicate ctx
        d <- readChan queue
        sendData ctx (L.fromChunks [d])
        byeBye ctx
    checkInfoPredicate ctx = do
        minfo <- contextGetInformation ctx
        unless (p minfo) $
            fail ("unexpected information: " ++ show minfo)

runTLSPipeSimple :: (ClientParams, ServerParams) -> IO ()
runTLSPipeSimple params = runTLSPipePredicate params (const True)

runTLSPipeSimple13
    :: (ClientParams, ServerParams)
    -> HandshakeMode13
    -> Maybe ByteString
    -> IO ()
runTLSPipeSimple13 params mode mEarlyData = runTLSPipe params tlsServer tlsClient
  where
    tlsServer ctx queue = do
        handshake ctx
        case mEarlyData of
            Nothing -> return ()
            Just ed -> do
                let ls = chunkLengths (B.length ed)
                chunks <- replicateM (length ls) $ recvData ctx
                (ls, ed) `shouldBe` (map B.length chunks, B.concat chunks)
        d <- recvData ctx
        checkCtxFinished ctx
        writeChan queue [d]
        minfo <- contextGetInformation ctx
        Just mode `shouldBe` (minfo >>= infoTLS13HandshakeMode)
        bye ctx
    tlsClient queue ctx = do
        handshake ctx
        checkCtxFinished ctx
        d <- readChan queue
        sendData ctx (L.fromChunks [d])
        minfo <- contextGetInformation ctx
        Just mode `shouldBe` (minfo >>= infoTLS13HandshakeMode)
        byeBye ctx

runTLSPipeCapture13
    :: (ClientParams, ServerParams) -> IO ([Handshake13], [Handshake13])
runTLSPipeCapture13 params = do
    sRef <- newIORef []
    cRef <- newIORef []
    runTLSPipe params (tlsServer sRef) (tlsClient cRef)
    sReceived <- readIORef sRef
    cReceived <- readIORef cRef
    return (reverse sReceived, reverse cReceived)
  where
    tlsServer ref ctx queue = do
        installHook ctx ref
        handshake ctx
        checkCtxFinished ctx
        d <- recvData ctx
        writeChan queue [d]
        bye ctx
    tlsClient ref queue ctx = do
        installHook ctx ref
        handshake ctx
        checkCtxFinished ctx
        d <- readChan queue
        sendData ctx (L.fromChunks [d])
        byeBye ctx
    installHook ctx ref =
        let recv hss = modifyIORef ref (hss :) >> return hss
         in contextHookSetHandshake13Recv ctx recv

runTLSPipeSimpleKeyUpdate :: (ClientParams, ServerParams) -> IO ()
runTLSPipeSimpleKeyUpdate params = runTLSPipeN 3 params tlsServer tlsClient
  where
    tlsServer ctx queue = do
        handshake ctx
        checkCtxFinished ctx
        d0 <- recvData ctx
        req <- generate $ elements [OneWay, TwoWay]
        _ <- updateKey ctx req
        d1 <- recvData ctx
        d2 <- recvData ctx
        writeChan queue [d0, d1, d2]
        bye ctx
    tlsClient queue ctx = do
        handshake ctx
        checkCtxFinished ctx
        d0 <- readChan queue
        sendData ctx (L.fromChunks [d0])
        d1 <- readChan queue
        sendData ctx (L.fromChunks [d1])
        req <- generate $ elements [OneWay, TwoWay]
        _ <- updateKey ctx req
        d2 <- readChan queue
        sendData ctx (L.fromChunks [d2])
        byeBye ctx

chunkLengths :: Int -> [Int]
chunkLengths len
    | len > 16384 = 16384 : chunkLengths (len - 16384)
    | len > 0 = [len]
    | otherwise = []

runTLSInitFailureGen
    :: (ClientParams, ServerParams)
    -> (Context -> IO s)
    -> (Context -> IO c)
    -> IO ()
runTLSInitFailureGen params hsServer hsClient = do
    (cRes, sRes) <- initiateDataPipe params tlsServer tlsClient
    cRes `shouldSatisfy` isLeft
    sRes `shouldSatisfy` isLeft
  where
    tlsServer ctx = do
        _ <- hsServer ctx
        checkCtxFinished ctx
        minfo <- contextGetInformation ctx
        byeBye ctx
        return $ "server success: " ++ show minfo
    tlsClient ctx = do
        _ <- hsClient ctx
        checkCtxFinished ctx
        minfo <- contextGetInformation ctx
        byeBye ctx
        return $ "client success: " ++ show minfo

runTLSInitFailure :: (ClientParams, ServerParams) -> IO ()
runTLSInitFailure params = runTLSInitFailureGen params handshake handshake

readClientSessionRef :: (IORef mclient, IORef mserver) -> IO mclient
readClientSessionRef refs = readIORef (fst refs)

twoSessionRefs :: IO (IORef (Maybe client), IORef (Maybe server))
twoSessionRefs = (,) <$> newIORef Nothing <*> newIORef Nothing

-- | simple session manager to store one session id and session data for a single thread.
-- a Real concurrent session manager would use an MVar and have multiples items.
oneSessionManager :: IORef (Maybe (SessionID, SessionData)) -> SessionManager
oneSessionManager ref =
    SessionManager
        { sessionResume = \myId -> readIORef ref >>= maybeResume False myId
        , sessionResumeOnlyOnce = \myId -> readIORef ref >>= maybeResume True myId
        , sessionEstablish = \myId dat -> writeIORef ref $ Just (myId, dat)
        , sessionInvalidate = \_ -> return ()
        }
  where
    maybeResume onlyOnce myId (Just (sid, sdata))
        | sid == myId = when onlyOnce (writeIORef ref Nothing) >> return (Just sdata)
    maybeResume _ _ _ = return Nothing

twoSessionManagers
    :: (IORef (Maybe (SessionID, SessionData)), IORef (Maybe (SessionID, SessionData)))
    -> (SessionManager, SessionManager)
twoSessionManagers (cRef, sRef) = (oneSessionManager cRef, oneSessionManager sRef)

setPairParamsSessionManagers
    :: (SessionManager, SessionManager)
    -> (ClientParams, ServerParams)
    -> (ClientParams, ServerParams)
setPairParamsSessionManagers (clientManager, serverManager) (clientState, serverState) = (nc, ns)
  where
    nc =
        clientState
            { clientShared = updateSessionManager clientManager $ clientShared clientState
            }
    ns =
        serverState
            { serverShared = updateSessionManager serverManager $ serverShared serverState
            }
    updateSessionManager manager shared = shared{sharedSessionManager = manager}

setPairParamsSessionResuming
    :: (SessionID, SessionData)
    -> (ClientParams, ServerParams)
    -> (ClientParams, ServerParams)
setPairParamsSessionResuming sessionStuff (clientState, serverState) =
    ( clientState{clientWantSessionResume = Just sessionStuff}
    , serverState
    )
