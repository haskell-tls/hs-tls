{-# LANGUAGE DeriveDataTypeable #-}
import Network
import System.IO
import System.Console.CmdArgs

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
	C.initiate handle
	C.sendData handle (L.pack $ map (toEnum.fromEnum) "GET / HTTP/1.0\r\n\r\n")

	d <- C.recvData handle
	lift $ L.putStrLn d

	d <- C.recvData handle
	lift $ L.putStrLn d

	return ()

getRandomGen :: IO SRandomGen
getRandomGen = makeSRandomGen >>= either (fail . show) (return . id)

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

mainServerAccept cert socket = do
	(h, d, _) <- accept socket
	forkIO $ clientProcess cert (h, d)
	mainServerAccept cert socket

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

data Stunnel =
	  Client { srcPort :: Int, destinationPort :: Int, destination :: String, sourceType :: String, source :: String }
	| Server { srcPort :: Int, destinationPort :: Int, destination :: String, certificate :: FilePath, key :: FilePath }
	deriving (Show, Data, Typeable)

clientOpts = Client
	{ srcPort         = 6060              &= help "port to listen on"  &= typ "PORT"
	, destinationPort = 6061              &= help "port to connect to" &= typ "PORT"
	, destination     = "localhost"       &= help "address to connect to" &= typ "ADDRESS"
	, sourceType      = "tcp"             &= help "type of source (tcp, unix, fd)" &= typ "SOURCETYPE"
	, source          = ""                &= help "source address influenced by source type" &= typ "ADDRESS"
	}
	&= help "connect to a remote destination that use SSL/TLS"

serverOpts = Server
	{ srcPort         = 6061              &= help "port to listen on"  &= typ "PORT"
	, destinationPort = 6060              &= help "port to connect to" &= typ "PORT"
	, destination     = "localhost"       &= help "address to connect to" &= typ "ADDRESS"
	, certificate     = "certificate.pem" &= help "X509 public certificate to use" &= typ "FILE"
	, key             = "certificate.key" &= help "private key linked to the certificate" &= typ "FILE"
	}
	&= help "listen for connection that use SSL/TLS and relay it to a different connection"

mode = cmdArgsMode $ modes [clientOpts,serverOpts]
	&= help "create SSL/TLS tunnel in client or server mode" &= program "stunnel" &= summary "Stunnel v0.1 (Haskell TLS)"

doClient :: Stunnel -> IO ()
doClient args = do
	let host = destination args
	let port = PortNumber $ fromIntegral $ destinationPort args

	rng <- getRandomGen

	handle <- connectTo host port
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

doServer :: Stunnel -> IO ()
doServer args = do
	let port = PortNumber $ fromIntegral $ srcPort args
	cert <- readCertificate $ certificate args
	pk   <- readPrivateKey $ key args
	bracket
		(listenOn port)
		sClose
		(mainServerAccept (cert, snd pk))

main = do
	args <- cmdArgsRun mode
	case args of
		Client _ _ _ _ _ -> doClient args
		Server _ _ _ _ _ -> doServer args
