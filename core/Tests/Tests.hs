{-# LANGUAGE CPP #-}

import Test.QuickCheck
import Test.QuickCheck.Monadic
import Test.Framework (defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)

import PipeChan
import Connection
import Marshalling
import Ciphers

import Data.Maybe

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as L
import Network.TLS
import Control.Applicative
import Control.Concurrent
import Control.Monad

import Data.IORef

prop_pipe_work :: PropertyM IO ()
prop_pipe_work = do
    pipe <- run newPipe
    _ <- run (runPipe pipe)

    let bSize = 16
    n <- pick (choose (1, 32))

    let d1 = B.replicate (bSize * n) 40
    let d2 = B.replicate (bSize * n) 45

    d1' <- run (writePipeA pipe d1 >> readPipeB pipe (B.length d1))
    d1 `assertEq` d1'

    d2' <- run (writePipeB pipe d2 >> readPipeA pipe (B.length d2))
    d2 `assertEq` d2'

    return ()

recvDataNonNull ctx = recvData ctx >>= \l -> if B.null l then recvDataNonNull ctx else return l

runTLSPipe params tlsServer tlsClient = do
    (startQueue, resultQueue) <- run (establishDataPipe params tlsServer tlsClient)
    -- send some data
    d <- B.pack <$> pick (someWords8 256)
    run $ writeChan startQueue d
    -- receive it
    dres <- run $ readChan resultQueue
    -- check if it equal
    d `assertEq` dres
    return ()

prop_handshake_initiate :: PropertyM IO ()
prop_handshake_initiate = do
    params  <- pick arbitraryPairParams
    runTLSPipe params tlsServer tlsClient
  where tlsServer ctx queue = do
            handshake ctx
            d <- recvDataNonNull ctx
            writeChan queue d
            return ()
        tlsClient queue ctx = do
            handshake ctx
            d <- readChan queue
            sendData ctx (L.fromChunks [d])
            bye ctx
            return ()

prop_handshake_npn_initiate :: PropertyM IO ()
prop_handshake_npn_initiate = do
    (clientParam,serverParam) <- pick arbitraryPairParams
    let clientParam' = clientParam { clientHooks = (clientHooks clientParam)
                                       { onNPNServerSuggest = Just $ \protos -> return (head protos) }
                                    }
        serverParam' = serverParam { serverHooks = (serverHooks serverParam)
                                        { onSuggestNextProtocols = return $ Just [C8.pack "spdy/2", C8.pack "http/1.1"] }
                                   }
        params' = (clientParam',serverParam')
    runTLSPipe params' tlsServer tlsClient
  where tlsServer ctx queue = do
            handshake ctx
            proto <- getNegotiatedProtocol ctx
            Just (C8.pack "spdy/2") `assertEq` proto
            d <- recvDataNonNull ctx
            writeChan queue d
            return ()
        tlsClient queue ctx = do
            handshake ctx
            proto <- getNegotiatedProtocol ctx
            Just (C8.pack "spdy/2") `assertEq` proto
            d <- readChan queue
            sendData ctx (L.fromChunks [d])
            bye ctx
            return ()

prop_handshake_renegociation :: PropertyM IO ()
prop_handshake_renegociation = do
    params <- pick arbitraryPairParams
    runTLSPipe params tlsServer tlsClient
  where tlsServer ctx queue = do
            handshake ctx
            d <- recvDataNonNull ctx
            writeChan queue d
            return ()
        tlsClient queue ctx = do
            handshake ctx
            handshake ctx
            d <- readChan queue
            sendData ctx (L.fromChunks [d])
            bye ctx
            return ()

-- | simple session manager to store one session id and session data for a single thread.
-- a Real concurrent session manager would use an MVar and have multiples items.
oneSessionManager :: IORef (Maybe (SessionID, SessionData)) -> SessionManager
oneSessionManager ref = SessionManager
    { sessionResume     = \myId     -> (>>= maybeResume myId) <$> readIORef ref
    , sessionEstablish  = \myId dat -> writeIORef ref $ Just (myId, dat)
    , sessionInvalidate = \_        -> return ()
    }
  where
    maybeResume myId (sid, sdata)
        | sid == myId = Just sdata
        | otherwise   = Nothing

prop_handshake_session_resumption :: PropertyM IO ()
prop_handshake_session_resumption = do
    sessionRef <- run $ newIORef Nothing
    let sessionManager = oneSessionManager sessionRef

    plainParams <- pick arbitraryPairParams
    let params = setPairParamsSessionManager sessionManager plainParams

    runTLSPipe params tlsServer tlsClient

    -- and resume
    sessionParams <- run $ readIORef sessionRef
    assert (isJust sessionParams)
    let params2 = setPairParamsSessionResuming (fromJust sessionParams) params

    runTLSPipe params2 tlsServer tlsClient
  where tlsServer ctx queue = do
            handshake ctx
            d <- recvDataNonNull ctx
            writeChan queue d
            return ()
        tlsClient queue ctx = do
            handshake ctx
            d <- readChan queue
            sendData ctx (L.fromChunks [d])
            bye ctx
            return ()

assertEq :: (Show a, Monad m, Eq a) => a -> a -> m ()
assertEq expected got = unless (expected == got) $ error ("got " ++ show got ++ " but was expecting " ++ show expected)

main :: IO ()
main = defaultMain
    [ tests_marshalling
    , tests_ciphers
    , tests_handshake
    ]
  where -- lowlevel tests to check the packet marshalling.
        tests_marshalling = testGroup "Marshalling"
            [ testProperty "Header" prop_header_marshalling_id
            , testProperty "Handshake" prop_handshake_marshalling_id
            ]
        tests_ciphers = testGroup "Ciphers"
            [ testProperty "Bulk" propertyBulkFunctional ]

        -- high level tests between a client and server with fake ciphers.
        tests_handshake = testGroup "Handshakes"
            [ testProperty "setup" (monadicIO prop_pipe_work)
            , testProperty "initiate" (monadicIO prop_handshake_initiate)
            , testProperty "npnInitiate" (monadicIO prop_handshake_npn_initiate)
            , testProperty "renegociation" (monadicIO prop_handshake_renegociation)
            , testProperty "resumption" (monadicIO prop_handshake_session_resumption)
            ]
