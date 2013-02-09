{-# LANGUAGE CPP #-}

module Tests.Connection (runTests) where

import Test.QuickCheck
import Test.QuickCheck.Test
import Test.QuickCheck.Monadic as QM

import Tests.Common
import Tests.Certificate

import Text.Printf
import Data.Word
import Test.QuickCheck
import Test.QuickCheck.Test
import Test.QuickCheck.Monadic as QM

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Data.Either
import Data.PEM
import Data.Certificate.X509
import qualified Data.Certificate.KeyRSA as KeyRSA
import qualified Crypto.Random.AESCtr as RNG
import Network.TLS
import Network.TLS.Extra.File
import Control.Monad
import Control.Monad.Trans (lift)
import Control.Applicative ((<$>))
import Control.Concurrent.Chan
import Control.Concurrent
import Control.Exception (throw, SomeException)
import qualified Control.Exception as E
import System.IO

import Network.Socket

someWords8 :: Int -> Gen [Word8] 
someWords8 i = replicateM i (fromIntegral <$> (choose (0,255) :: Gen Int))

#if MIN_VERSION_QuickCheck(2,3,0)
#else
instance Arbitrary Word8 where
	arbitrary = fromIntegral <$> (choose (0,255) :: Gen Int)
#endif

arbitraryVersions :: Gen [Version]
arbitraryVersions = resize (length supportedVersions + 1) $ listOf1 (elements supportedVersions)
arbitraryCiphers  = resize (length supportedCiphers + 1) $ listOf1 (elements supportedCiphers)

{- | create a client params and server params that is supposed to
 - result in a valid connection -}
makeValidParams serverCerts = do
	-- it should also generate certificates, key exchange parameters
	-- here instead of taking them from outside.
	-- cert <- arbitraryX509 (PubKey SignatureALG_rsa (PubKeyRSA (0,0,0)))
	allowedVersions <- arbitraryVersions
	connectVersion  <- elements supportedVersions `suchThat` (\c -> c `elem` allowedVersions)

	serverCiphers <- arbitraryCiphers
	clientCiphers <- oneof [arbitraryCiphers] `suchThat`
	                 (\cs -> or [x `elem` serverCiphers | x <- cs])
	secNeg <- arbitrary

	let serverState = defaultParamsServer
		{ pAllowedVersions        = allowedVersions
		, pCiphers                = serverCiphers
		, pCertificates           = serverCerts
		, pUseSecureRenegotiation = secNeg
		}

	let clientState = defaultParamsClient
		{ pConnectVersion         = connectVersion
		, pAllowedVersions        = allowedVersions
		, pCiphers                = clientCiphers
		, pUseSecureRenegotiation = secNeg
		}

	return (clientState, serverState)

{- | setup create all necessary connection point to create a data "pipe"
 -   ---(startQueue)---> tlsClient ---(socketPair)---> tlsServer ---(resultQueue)--->
 -}
setup :: (TLSParams, TLSParams) -> IO (Context, Context, Chan a, Chan a)
setup (clientState, serverState) = do
	(cSocket, sSocket) <- socketPair AF_UNIX Stream defaultProtocol
	cHandle            <- socketToHandle cSocket ReadWriteMode
	sHandle            <- socketToHandle sSocket ReadWriteMode

	hSetBuffering cHandle NoBuffering
	hSetBuffering sHandle NoBuffering

	clientRNG   <- RNG.makeSystem
	serverRNG   <- RNG.makeSystem
	startQueue  <- newChan
	resultQueue <- newChan

	cCtx <- contextNewOnHandle cHandle clientState clientRNG
	sCtx <- contextNewOnHandle sHandle serverState serverRNG

	return (cCtx, sCtx, startQueue, resultQueue)

testInitiate spCert = do
	states <- pick (makeValidParams spCert)
	(cCtx, sCtx, startQueue, resultQueue) <- run (setup states)

	run $ forkIO $ do
		E.catch (tlsServer sCtx resultQueue)
		      (\e -> putStrLn ("server exception: " ++ show e) >> throw (e :: SomeException))
		return ()
	run $ forkIO $ do
		E.catch (tlsClient startQueue cCtx)
		      (\e -> putStrLn ("client exception: " ++ show e) >> throw (e :: SomeException))
		return ()

	{- the test involves writing data on one side of the data "pipe" and
	 - then checking we received them on the other side of the data "pipe" -}
	d <- B.pack <$> pick (someWords8 256)
	run $ writeChan startQueue d

	dres <- run $ readChan resultQueue
	assertEq d dres

	-- cleanup
	run (contextClose cCtx >> contextClose sCtx)

	where
		assertEq exp got
			| exp == got = return ()
			| otherwise  = error ("expected: " ++ show exp ++ "\n    got: " ++ show got)

		tlsServer handle queue = do
			handshake handle
			d <- recvData handle
			writeChan queue d
			return ()
		tlsClient queue handle = do
			handshake handle
			d <- readChan queue
			sendData handle (L.fromChunks [d])
			return ()

runTests = do
	{- FIXME generate the certificate and key with arbitrary, for now rely on special files -}
	cert <- fileReadCertificate "server.crt"
	pk   <- fileReadPrivateKey "server.key"

	run_test "initiate" (monadicIO $ testInitiate [(cert, Just pk)])
