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

import Data.Certificate.PEM
import Data.Certificate.X509
import qualified Data.Certificate.KeyRSA as KeyRSA
import qualified Network.TLS.Client as C
import qualified Network.TLS.Server as S
import Network.TLS.Crypto
import Network.TLS.Cipher
import Network.TLS.Core
import Network.TLS.Struct
import Network.TLS.Packet
import Network.TLS.SRandom
import Network.Socket
import Control.Monad
import Control.Monad.Trans (lift)
import Control.Applicative ((<$>))
import Control.Concurrent.Chan
import Control.Concurrent
import Control.Exception (catch, throw, SomeException)
import System.IO

import qualified Data.Certificate.KeyRSA as KeyRSA
import qualified Crypto.Cipher.RSA as RSA

import Prelude hiding (catch)

someWords8 :: Int -> Gen [Word8] 
someWords8 i = replicateM i (fromIntegral <$> (choose (0,255) :: Gen Int))

#if MIN_VERSION_QuickCheck(2,3,0)
#else
instance Arbitrary Word8 where
	arbitrary = fromIntegral <$> (choose (0,255) :: Gen Int)
#endif

{- helpers to prepare the tests -}
getRandomGen :: IO SRandomGen
getRandomGen = makeSRandomGen >>= either (fail . show) (return . id)

readCertificate :: FilePath -> IO X509
readCertificate filepath = do
	content <- B.readFile filepath
	let certdata = case parsePEMCert content of
		Nothing -> error ("no valid certificate section")
		Just x  -> x
	let cert = case decodeCertificate $ L.fromChunks [certdata] of
		Left err -> error ("cannot decode certificate: " ++ err)
		Right x  -> x
	return cert

readPrivateKey :: FilePath -> IO PrivateKey
readPrivateKey filepath = do
	content <- B.readFile filepath
	let pkdata = case parsePEMKeyRSA content of
		Nothing -> error ("no valid RSA key section")
		Just x  -> L.fromChunks [x]
	let pk = case KeyRSA.decodePrivate pkdata of
		Left err -> error ("cannot decode key: " ++ err)
		Right x  -> PrivRSA $ RSA.PrivateKey
			{ RSA.private_sz   = fromIntegral $ KeyRSA.lenmodulus x
			, RSA.private_n    = KeyRSA.modulus x
			, RSA.private_d    = KeyRSA.private_exponant x
			, RSA.private_p    = KeyRSA.p1 x
			, RSA.private_q    = KeyRSA.p2 x
			, RSA.private_dP   = KeyRSA.exp1 x
			, RSA.private_dQ   = KeyRSA.exp2 x
			, RSA.private_qinv = KeyRSA.coef x
			}
	return pk

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

	let serverState = defaultParams
		{ pAllowedVersions = allowedVersions
		, pCiphers         = serverCiphers
		, pCertificates    = serverCerts
		}

	let clientState = defaultParams
		{ pConnectVersion  = connectVersion
		, pAllowedVersions = allowedVersions
		, pCiphers         = clientCiphers
		}

	return (clientState, serverState)

{- | setup create all necessary connection point to create a data "pipe"
 -   ---(startQueue)---> tlsClient ---(socketPair)---> tlsServer ---(resultQueue)--->
 -}
setup :: IO (Handle, Handle, SRandomGen, SRandomGen, Chan a, Chan a)
setup = do
	(cSocket, sSocket) <- socketPair AF_UNIX Stream defaultProtocol
	cHandle            <- socketToHandle cSocket ReadWriteMode
	sHandle            <- socketToHandle sSocket ReadWriteMode

	hSetBuffering cHandle NoBuffering
	hSetBuffering sHandle NoBuffering

	clientRNG   <- getRandomGen
	serverRNG   <- getRandomGen
	startQueue  <- newChan
	resultQueue <- newChan

	return (cHandle, sHandle, clientRNG, serverRNG, startQueue, resultQueue)

testInitiate spCert = do
	(clientstate, serverstate) <- pick (makeValidParams spCert)
	(cHandle, sHandle, clientRNG, serverRNG, startQueue, resultQueue) <- run setup

	run $ forkIO $ do
		catch (S.runTLSServer (tlsServer sHandle resultQueue) serverstate serverRNG)
		      (\e -> putStrLn ("server exception: " ++ show e) >> throw (e :: SomeException))
		return ()
	run $ forkIO $ do
		catch (C.runTLSClient (tlsClient startQueue cHandle) clientstate clientRNG)
		      (\e -> putStrLn ("client exception: " ++ show e) >> throw (e :: SomeException))
		return ()

	{- the test involves writing data on one side of the data "pipe" and
	 - then checking we receive them on the other side of the data "pipe" -}
	d <- L.pack <$> pick (someWords8 256)
	run $ writeChan startQueue d

	dres <- run $ readChan resultQueue
	assert $ d == dres

	-- cleanup
	run $ (hClose cHandle >> hClose sHandle)

	where
		tlsServer handle queue = do
			S.listen handle
			d <- S.recvData handle
			lift $ writeChan queue d
			return ()
		tlsClient queue handle = do
			C.initiate handle
			d <- lift $ readChan queue
			C.sendData handle d
			return ()

runTests = do
	{- FIXME generate the certificate and key with arbitrary, for now rely on special files -}
	cert <- readCertificate "host.cert"
	pk   <- readPrivateKey "host.key"

	run_test "initiate" (monadicIO $ testInitiate [(cert, Just pk)])
