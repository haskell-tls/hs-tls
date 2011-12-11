{-# LANGUAGE CPP #-}

import Test.QuickCheck
import Test.QuickCheck.Monadic
import Test.Framework (defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)

import Tests.Certificate
import Tests.PipeChan
import Tests.Connection

import Data.Word

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Network.TLS.Core
import Network.TLS.Cipher
import Network.TLS.Struct
import Network.TLS.Packet
import Control.Applicative
import Control.Concurrent
import Control.Exception (throw, catch, SomeException)
import Control.Monad

import Prelude hiding (catch)

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
		, ServerHello
			<$> arbitrary
			<*> arbitrary
			<*> arbitrary
			<*> arbitrary
			<*> arbitrary
			<*> (return [])
		, liftM Certificates (resize 2 $ listOf $ arbitraryX509)
		, pure HelloRequest
		, pure ServerHelloDone
		, ClientKeyXchg <$> genByteString 48
		--, liftM  ServerKeyXchg
		--, liftM3 CertRequest arbitrary (return Nothing) (return [])
		--, liftM CertVerify (return [])
		, Finished <$> (genByteString 12)
		]

{- quickcheck property -}

prop_header_marshalling_id :: Header -> Bool
prop_header_marshalling_id x = (decodeHeader $ encodeHeader x) == Right x

prop_handshake_marshalling_id :: Handshake -> Bool
prop_handshake_marshalling_id x = (decodeHs $ encodeHandshake x) == Right x
	where
		decodeHs b = either (Left . id) (uncurry (decodeHandshake cp) . head) $ decodeHandshakes b
		cp = CurrentParams { cParamsVersion = TLS10, cParamsKeyXchgType = CipherKeyExchange_RSA }

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

	_ <- forkIO $ catch (tlsServer sCtx resultQueue) (printAndRaise "server")
	_ <- forkIO $ catch (tlsClient startQueue cCtx) (printAndRaise "client")

	return (startQueue, resultQueue)
	where
		printAndRaise :: String -> SomeException -> IO ()
		printAndRaise s e = putStrLn (s ++ " exception: " ++ show e) >> throw e

prop_handshake_initiate :: PropertyM IO ()
prop_handshake_initiate = do
	params       <- pick arbitraryPairParams
	(startQueue, resultQueue) <- run (establish_data_pipe params tlsServer tlsClient)

	{- the test involves writing data on one side of the data "pipe" and
	 - then checking we received them on the other side of the data "pipe" -}
	d <- L.pack <$> pick (someWords8 256)
	run $ writeChan startQueue d

	dres <- run $ readChan resultQueue
	d `assertEq` dres

	return ()
	where
		tlsServer ctx queue = do
			hSuccess <- handshake ctx
			unless hSuccess $ fail "handshake failed on server side"
			d <- recvData ctx
			writeChan queue d
			return ()
		tlsClient queue ctx = do
			hSuccess <- handshake ctx
			unless hSuccess $ fail "handshake failed on client side"
			d <- readChan queue
			sendData ctx d
			bye ctx
			return ()

prop_handshake_renegociation :: PropertyM IO ()
prop_handshake_renegociation = do
	params       <- pick arbitraryPairParams
	(startQueue, resultQueue) <- run (establish_data_pipe params tlsServer tlsClient)

	{- the test involves writing data on one side of the data "pipe" and
	 - then checking we received them on the other side of the data "pipe" -}
	d <- L.pack <$> pick (someWords8 256)
	run $ writeChan startQueue d

	dres <- run $ readChan resultQueue
	d `assertEq` dres

	return ()
	where
		tlsServer ctx queue = do
			hSuccess <- handshake ctx
			unless hSuccess $ fail "handshake failed on server side"
			d <- recvData ctx
			writeChan queue d
			return ()
		tlsClient queue ctx = do
			hSuccess <- handshake ctx
			unless hSuccess $ fail "handshake failed on client side"
			hSuccess2 <- handshake ctx
			unless hSuccess $ fail "renegociation handshake failed"
			d <- readChan queue
			sendData ctx d
			bye ctx
			return ()

assertEq :: (Show a, Monad m, Eq a) => a -> a -> m ()
assertEq expected got = unless (expected == got) $ error ("got " ++ show got ++ " but was expecting " ++ show expected)

main :: IO ()
main = defaultMain
	[ tests_marshalling
	, tests_handshake
	]
	where
		-- lowlevel tests to check the packet marshalling.
		tests_marshalling = testGroup "Marshalling"
			[ testProperty "Header" prop_header_marshalling_id
			, testProperty "Handshake" prop_handshake_marshalling_id
			]

		-- high level tests between a client and server with fake ciphers.
		tests_handshake = testGroup "Handshakes"
			[ testProperty "setup" (monadicIO prop_pipe_work)
			, testProperty "initiate" (monadicIO prop_handshake_initiate)
			, testProperty "renegociation" (monadicIO prop_handshake_renegociation)
			]
