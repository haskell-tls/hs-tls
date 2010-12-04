{-# LANGUAGE CPP #-}

module Tests.Connection (runTests) where

import Test.QuickCheck
import Test.QuickCheck.Test
import Test.QuickCheck.Monadic as QM

import Tests.Common

import Text.Printf
import Data.Word
import Test.QuickCheck
import Test.QuickCheck.Test
import Test.QuickCheck.Monadic as QM

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Data.Certificate.PEM
import Data.Certificate.X509
import Data.Certificate.Key
import qualified Network.TLS.Client as C
import qualified Network.TLS.Server as S
import Network.TLS.Cipher
import Network.TLS.Struct
import Network.TLS.Packet
import Network.TLS.SRandom
import Network.Socket
import Control.Monad
import Control.Monad.Trans (lift)
import Control.Applicative ((<$>))
import Control.Concurrent.Chan
import Control.Concurrent
import System.IO

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

readCertificate :: FilePath -> IO (B.ByteString, Certificate)
readCertificate filepath = do
	content <- B.readFile filepath
	let certdata = case parsePEMCert content of
		Nothing -> error ("no valid certificate section")
		Just x  -> x
	let cert = case decodeCertificate $ L.fromChunks [certdata] of
		Left err -> error ("cannot decode certificate: " ++ err)
		Right x  -> x
	return (certdata, cert)

readPrivateKey :: FilePath -> IO (L.ByteString, PrivateKey)
readPrivateKey filepath = do
	content <- B.readFile filepath
	let pkdata = case parsePEMKeyRSA content of
		Nothing -> error ("no valid RSA key section")
		Just x  -> L.fromChunks [x]
	let pk = case decodePrivateKey pkdata of
		Left err -> error ("cannot decode key: " ++ err)
		Right x  -> x
	return (pkdata, pk)

{- | create a client params and server params that is supposed to
 - result in a valid connection -}
makeValidParams spCert = do
	let ciphers =
		[ cipher_AES128_SHA1
		, cipher_AES256_SHA1
		, cipher_RC4_128_MD5
		, cipher_RC4_128_SHA1
		]

	let serverstate = S.TLSServerParams
		{ S.spAllowedVersions = [TLS10,TLS11]
		, S.spSessions = []
		, S.spCiphers = ciphers
		, S.spCertificate = Just spCert
		, S.spWantClientCert = False
		, S.spCallbacks = S.TLSServerCallbacks
			{ S.cbCertificates = Nothing }
		}
	let clientstate = C.TLSClientParams
		{ C.cpConnectVersion = TLS10
		, C.cpAllowedVersions = [ TLS10, TLS11 ]
		, C.cpSession = Nothing
		, C.cpCiphers = ciphers
		, C.cpCertificate = Nothing
		, C.cpCallbacks = C.TLSClientCallbacks
			{ C.cbCertificates = Nothing
			}
		}
	return (clientstate, serverstate)

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

testInitiate (clientstate, serverstate) = do
	(cHandle, sHandle, clientRNG, serverRNG, startQueue, resultQueue) <- run setup

	run $ forkIO $ do
		S.runTLSServer (tlsServer sHandle resultQueue) serverstate serverRNG
		return ()
	run $ forkIO $ do
		C.runTLSClient (tlsClient startQueue cHandle) clientstate clientRNG
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
	(certdata, cert)   <- readCertificate "host.cert"
	pk                 <- readPrivateKey "host.key"

	let spCert = (certdata, cert, snd pk)

	run_test "initiate" (monadicIO $ makeValidParams spCert >>= testInitiate)
