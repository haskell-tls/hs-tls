{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Run (
    runTLSPipe,
    runTLSPipeSimple,
    runTLSPipePredicate,
    runTLSPipePredicate2,
    runTLSPipeSimple13,
    runTLSPipeSimpleKeyUpdate,
    runTLSPipeCapture13,
    runTLSPipeFailure,
) where

import Control.Concurrent
import Control.Concurrent.Async
import qualified Control.Exception as E
import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Default.Class
import Data.IORef
import Network.TLS
import System.Timeout
import Test.Hspec
import Test.QuickCheck

import API
import Arbitrary
import PipeChan

type ClinetWithInput = Chan ByteString -> Context -> IO ()
type ServerWithOutput = Context -> Chan [ByteString] -> IO ()

----------------------------------------------------------------

runTLSPipe
    :: (ClientParams, ServerParams)
    -> ClinetWithInput
    -> ServerWithOutput
    -> IO ()
runTLSPipe = runTLSPipeN 1

runTLSPipeN
    :: Int
    -> (ClientParams, ServerParams)
    -> ClinetWithInput
    -> ServerWithOutput
    -> IO ()
runTLSPipeN n params tlsClient tlsServer = do
    inputChan <- newChan
    outputChan <- newChan
    -- generate some data to send
    ds <- replicateM n $ B.pack <$> generate (someWords8 256)
    forM_ ds $ writeChan inputChan
    -- run client and server
    (cCtx, sCtx) <- newPairContext params
    concurrently_ (server sCtx outputChan) (client inputChan cCtx)
    -- read result
    m_dsres <- timeout 60000000 $ readChan outputChan -- 60 sec
    case m_dsres of
        Nothing -> error "timed out"
        Just dsres -> dsres `shouldBe` ds
  where
    server sCtx outputChan =
        E.catch
            (tlsServer sCtx outputChan)
            (printAndRaise "server" (serverSupported $ snd params))
    client inputChan cCtx =
        E.catch
            (tlsClient inputChan cCtx)
            (printAndRaise "client" (clientSupported $ fst params))
    printAndRaise :: String -> Supported -> E.SomeException -> IO ()
    printAndRaise s supported e = do
        putStrLn $
            s
                ++ " exception: "
                ++ show e
                ++ ", supported: "
                ++ show supported
        E.throwIO e

----------------------------------------------------------------

runTLSPipeSimple :: (ClientParams, ServerParams) -> IO ()
runTLSPipeSimple params = runTLSPipePredicate params (const True)

runTLSPipePredicate
    :: (ClientParams, ServerParams) -> (Maybe Information -> Bool) -> IO ()
runTLSPipePredicate params p = runTLSPipe params tlsClient tlsServer
  where
    tlsClient queue ctx = do
        handshake ctx
        checkCtxFinished ctx
        checkInfoPredicate ctx
        d <- readChan queue
        sendData ctx (L.fromChunks [d])
        byeBye ctx
    tlsServer ctx queue = do
        handshake ctx
        checkCtxFinished ctx
        checkInfoPredicate ctx
        d <- recvData ctx
        writeChan queue [d]
        bye ctx
    checkInfoPredicate ctx = do
        minfo <- contextGetInformation ctx
        unless (p minfo) $
            fail ("unexpected information: " ++ show minfo)

runTLSPipePredicate2
    :: (ClientParams, ServerParams)
    -> (Context -> IO ())
    -> (Context -> IO ())
    -> IO ()
runTLSPipePredicate2 params checkClient checkServer =
    runTLSPipe params tlsClient tlsServer
  where
    tlsClient queue ctx = do
        handshake ctx
        checkCtxFinished ctx
        checkClient ctx
        d <- readChan queue
        sendData ctx (L.fromChunks [d])
        byeBye ctx
    tlsServer ctx queue = do
        handshake ctx
        checkCtxFinished ctx
        checkServer ctx
        d <- recvData ctx
        writeChan queue [d]
        bye ctx

----------------------------------------------------------------

runTLSPipeSimple13
    :: (ClientParams, ServerParams)
    -> HandshakeMode13
    -> Maybe ByteString
    -> IO ()
runTLSPipeSimple13 params mode mEarlyData = runTLSPipe params tlsClient tlsServer
  where
    tlsClient queue ctx = do
        handshake ctx
        checkCtxFinished ctx
        d <- readChan queue
        sendData ctx (L.fromChunks [d])
        minfo <- contextGetInformation ctx
        (minfo >>= infoTLS13HandshakeMode) `shouldBe` Just mode
        byeBye ctx
    tlsServer ctx queue = do
        handshake ctx
        case mEarlyData of
            Nothing -> return ()
            Just ed -> do
                let ls = chunkLengths (B.length ed)
                chunks <- replicateM (length ls) $ recvData ctx
                (map B.length chunks, B.concat chunks) `shouldBe` (ls, ed)
        d <- recvData ctx
        checkCtxFinished ctx
        writeChan queue [d]
        minfo <- contextGetInformation ctx
        (minfo >>= infoTLS13HandshakeMode) `shouldBe` Just mode
        bye ctx
    chunkLengths :: Int -> [Int]
    chunkLengths len
        | len > 16384 = 16384 : chunkLengths (len - 16384)
        | len > 0 = [len]
        | otherwise = []

runTLSPipeCapture13
    :: (ClientParams, ServerParams) -> IO ([Handshake13], [Handshake13])
runTLSPipeCapture13 params = do
    sRef <- newIORef []
    cRef <- newIORef []
    runTLSPipe params (tlsClient cRef) (tlsServer sRef)
    sReceived <- readIORef sRef
    cReceived <- readIORef cRef
    return (reverse sReceived, reverse cReceived)
  where
    tlsClient ref queue ctx = do
        installHook ctx ref
        handshake ctx
        checkCtxFinished ctx
        d <- readChan queue
        sendData ctx (L.fromChunks [d])
        byeBye ctx
    tlsServer ref ctx queue = do
        installHook ctx ref
        handshake ctx
        checkCtxFinished ctx
        d <- recvData ctx
        writeChan queue [d]
        bye ctx
    installHook ctx ref =
        let recv hss = modifyIORef ref (hss :) >> return hss
         in contextHookSetHandshake13Recv ctx recv

runTLSPipeSimpleKeyUpdate :: (ClientParams, ServerParams) -> IO ()
runTLSPipeSimpleKeyUpdate params = runTLSPipeN 3 params tlsClient tlsServer
  where
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

----------------------------------------------------------------

runTLSPipeFailure
    :: (ClientParams, ServerParams)
    -> (Context -> IO c)
    -> (Context -> IO s)
    -> IO ()
runTLSPipeFailure params hsClient hsServer = do
    (cCtx, sCtx) <- newPairContext params

    concurrently_ (tlsServer sCtx) (tlsClient cCtx)
  where
    tlsClient ctx =
        (void (hsClient ctx) >> byeBye ctx)
            `shouldThrow` anyTLSException
    tlsServer ctx =
        (void (hsServer ctx) >> byeBye ctx)
            `shouldThrow` anyTLSException

anyTLSException :: Selector TLSException
anyTLSException = const True

----------------------------------------------------------------

debug :: Bool
debug = False

newPairContext
    :: (ClientParams, ServerParams) -> IO (Context, Context)
newPairContext (cParams, sParams) = do
    pipe <- newPipe
    _ <- runPipe pipe
    let noFlush = return ()
    let noClose = return ()

    let cBackend = Backend noFlush noClose (writePipeC pipe) (readPipeC pipe)
    let sBackend = Backend noFlush noClose (writePipeS pipe) (readPipeS pipe)
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
