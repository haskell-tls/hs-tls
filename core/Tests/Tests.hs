{-# LANGUAGE CPP #-}

import Test.QuickCheck
import Test.QuickCheck.Monadic
import Test.Framework (defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)

import Certificate
import PipeChan
import Connection

import Data.Maybe
import Data.Word

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as L
import Network.TLS
import Network.TLS.Internal
import Control.Applicative
import Control.Concurrent
import Control.Exception (throw, SomeException)
import qualified Control.Exception as E
import Control.Monad

import Data.IORef
import Data.X509

genByteString :: Int -> Gen B.ByteString
genByteString i = B.pack <$> vector i

instance Arbitrary Version where
    arbitrary = elements [ SSL2, SSL3, TLS10, TLS11, TLS12 ]

instance Arbitrary ProtocolType where
    arbitrary = elements
            [ ProtocolType_ChangeCipherSpec
            , ProtocolType_Alert
            , ProtocolType_Handshake
            , ProtocolType_AppData ]

#if MIN_VERSION_QuickCheck(2,3,0)
#else
instance Arbitrary Word8 where
    arbitrary = fromIntegral <$> (choose (0,255) :: Gen Int)

instance Arbitrary Word16 where
    arbitrary = fromIntegral <$> (choose (0,65535) :: Gen Int)
#endif

instance Arbitrary Header where
    arbitrary = Header <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary ClientRandom where
    arbitrary = ClientRandom <$> (genByteString 32)

instance Arbitrary ServerRandom where
    arbitrary = ServerRandom <$> (genByteString 32)

instance Arbitrary Session where
    arbitrary = do
        i <- choose (1,2) :: Gen Int
        case i of
            2 -> liftM (Session . Just) (genByteString 32)
            _ -> return $ Session Nothing

instance Arbitrary CertVerifyData where
    arbitrary = liftM CertVerifyData (genByteString 128)

arbitraryCiphersIDs :: Gen [Word16]
arbitraryCiphersIDs = choose (0,200) >>= vector

arbitraryCompressionIDs :: Gen [Word8]
arbitraryCompressionIDs = choose (0,200) >>= vector

someWords8 :: Int -> Gen [Word8]
someWords8 i = replicateM i (fromIntegral <$> (choose (0,255) :: Gen Int))

instance Arbitrary CertificateType where
    arbitrary = elements
            [ CertificateType_RSA_Sign, CertificateType_DSS_Sign
            , CertificateType_RSA_Fixed_DH, CertificateType_DSS_Fixed_DH
            , CertificateType_RSA_Ephemeral_DH, CertificateType_DSS_Ephemeral_DH
            , CertificateType_fortezza_dms ]

instance Arbitrary Handshake where
    arbitrary = oneof
            [ ClientHello
                <$> arbitrary
                <*> arbitrary
                <*> arbitrary
                <*> arbitraryCiphersIDs
                <*> arbitraryCompressionIDs
                <*> (return [])
                <*> (return Nothing)
            , ServerHello
                <$> arbitrary
                <*> arbitrary
                <*> arbitrary
                <*> arbitrary
                <*> arbitrary
                <*> (return [])
            , liftM Certificates (CertificateChain <$> (resize 2 $ listOf $ arbitraryX509))
            , pure HelloRequest
            , pure ServerHelloDone
            , ClientKeyXchg <$> genByteString 48
            --, liftM  ServerKeyXchg
            , liftM3 CertRequest arbitrary (return Nothing) (return [])
            , liftM2 CertVerify (return Nothing) arbitrary
            , Finished <$> (genByteString 12)
            ]

{- quickcheck property -}

prop_header_marshalling_id :: Header -> Bool
prop_header_marshalling_id x = (decodeHeader $ encodeHeader x) == Right x

prop_handshake_marshalling_id :: Handshake -> Bool
prop_handshake_marshalling_id x = (decodeHs $ encodeHandshake x) == Right x
  where decodeHs b = either (Left . id) (uncurry (decodeHandshake cp) . head) $ decodeHandshakes b
        cp = CurrentParams { cParamsVersion = TLS10, cParamsKeyXchgType = CipherKeyExchange_RSA, cParamsSupportNPN = True }

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

establish_data_pipe params tlsServer tlsClient = do
    -- initial setup
    pipe        <- newPipe
    _           <- (runPipe pipe)
    startQueue  <- newChan
    resultQueue <- newChan

    (cCtx, sCtx) <- newPairContext pipe params

    _ <- forkIO $ E.catch (tlsServer sCtx resultQueue) (printAndRaise "server")
    _ <- forkIO $ E.catch (tlsClient startQueue cCtx) (printAndRaise "client")

    return (startQueue, resultQueue)
  where
        printAndRaise :: String -> SomeException -> IO ()
        printAndRaise s e = putStrLn (s ++ " exception: " ++ show e) >> throw e

recvDataNonNull ctx = recvData ctx >>= \l -> if B.null l then recvDataNonNull ctx else return l

runTLSPipe params tlsServer tlsClient = do
    (startQueue, resultQueue) <- run (establish_data_pipe params tlsServer tlsClient)
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
    let clientParam' = updateClientParams (\cp -> cp { onNPNServerSuggest = Just $ \protos -> return (head protos) }) clientParam
        serverParam' = updateServerParams (\sp -> sp { onSuggestNextProtocols = return $ Just [C8.pack "spdy/2", C8.pack "http/1.1"] }) serverParam
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
    , tests_handshake
    ]
  where -- lowlevel tests to check the packet marshalling.
        tests_marshalling = testGroup "Marshalling"
            [ testProperty "Header" prop_header_marshalling_id
            , testProperty "Handshake" prop_handshake_marshalling_id
            ]

        -- high level tests between a client and server with fake ciphers.
        tests_handshake = testGroup "Handshakes"
            [ testProperty "setup" (monadicIO prop_pipe_work)
            , testProperty "initiate" (monadicIO prop_handshake_initiate)
            , testProperty "initiate with npn" (monadicIO prop_handshake_npn_initiate)
            , testProperty "renegociation" (monadicIO prop_handshake_renegociation)
            , testProperty "resumption" (monadicIO prop_handshake_session_resumption)
            ]
