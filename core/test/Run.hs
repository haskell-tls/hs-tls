module Run (
    checkCtxFinished,
    recvDataAssert,
    byeBye,
    runTLSPipe,
) where

import Control.Concurrent
import Control.Concurrent.Async
import qualified Control.Exception as E
import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Default.Class
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
