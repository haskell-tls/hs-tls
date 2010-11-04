import Network
import System.IO
import System

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Char8 as LC

import Control.Applicative ((<$>))
import Control.Concurrent (forkIO)
import Control.Exception (bracket)
import Control.Monad (forM_, when, replicateM)
import Control.Monad.Trans (lift)

import Data.Word
import Data.Bits
import Data.Maybe

import Data.Certificate.PEM
import Data.Certificate.X509
import Data.Certificate.Key

import Network.TLS.Cipher
import Network.TLS.SRandom
import Network.TLS.Struct
import Network.TLS.MAC

import qualified Network.TLS.Client as C
import qualified Network.TLS.Server as S

ciphers :: [Cipher]
ciphers =
	[ cipher_AES128_SHA1
	, cipher_AES256_SHA1
	, cipher_RC4_128_MD5
	, cipher_RC4_128_SHA1
	]

conv :: [Word8] -> Int
conv l = (a `shiftL` 24) .|. (b `shiftL` 16) .|. (c `shiftL` 8) .|. d
	where
		[a,b,c,d] = map fromIntegral l

tlsclient handle = do
	C.connect handle
	C.sendData handle (L.pack $ map (toEnum.fromEnum) "GET / HTTP/1.0\r\n\r\n")

	d <- C.recvData handle
	lift $ L.putStrLn d

	d <- C.recvData handle
	lift $ L.putStrLn d

	return ()

getRandomGen :: IO SRandomGen
getRandomGen = makeSRandomGen >>= either (fail . show) (return . id)

mainClient :: String -> Int -> IO ()
mainClient host port = do
	rng <- getRandomGen

	handle <- connectTo host (PortNumber $ fromIntegral port)
	hSetBuffering handle NoBuffering

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
	C.runTLSClient (tlsclient handle) clientstate rng

	putStrLn "end"

tlsserver handle = do
	S.listen handle
	_ <- S.recvData handle
	S.sendData handle (LC.pack "this is some data")
	lift $ hFlush handle
	lift $ putStrLn "end"

clientProcess ((certdata, cert), pk) (handle, src) = do
	rng <- getRandomGen

	let serverstate = S.TLSServerParams
		{ S.spAllowedVersions = [TLS10,TLS11]
		, S.spSessions = []
		, S.spCiphers = ciphers
		, S.spCertificate = Just (certdata, cert, pk)
		, S.spWantClientCert = False
		, S.spCallbacks = S.TLSServerCallbacks
			{ S.cbCertificates = Nothing }
		}

	S.runTLSServer (tlsserver handle) serverstate rng
	putStrLn "end"

mainServerAccept cert port socket = do
	(h, d, _) <- accept socket
	forkIO $ clientProcess cert (h, d)
	mainServerAccept cert port socket

mainServer cert port = bracket (listenOn (PortNumber port)) (sClose) (mainServerAccept cert port)

usage :: IO ()
usage = do
	putStrLn "usage: stunnel [client|server] <params...>"
	exitFailure

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

main = do
	args <- getArgs
	when (length args == 0) usage
	case (args !! 0) of
		"server" -> do
			cert <- readCertificate (args !! 1)
			pk <- readPrivateKey (args !! 2)
			mainServer (cert, snd pk) 6061
		"client" -> do
			let port =
				if length args > 1
					then read $ args !! 1
					else 6061
			let dest =
				if length args > 2
					then args !! 2
					else "localhost"
			mainClient dest port
		_        -> usage
