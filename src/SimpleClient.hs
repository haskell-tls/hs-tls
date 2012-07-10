{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
import Network.BSD
import Network.Socket
import Network.TLS
import Network.TLS.Extra
import System.IO
import qualified Crypto.Random.AESCtr as RNG
import qualified Data.ByteString.Lazy.Char8 as LC
import Control.Exception
import System.Environment
import Prelude hiding (catch)

import Data.IORef

validateCert = True
debug = False

ciphers :: [Cipher]
ciphers =
	[ cipher_AES128_SHA1
	, cipher_AES256_SHA1
	, cipher_RC4_128_MD5
	, cipher_RC4_128_SHA1
	]

runTLS params hostname portNumber f = do
	rng  <- RNG.makeSystem
	he   <- getHostByName hostname
	sock <- socket AF_INET Stream defaultProtocol
	let sockaddr = SockAddrInet portNumber (head $ hostAddresses he)
	catch (connect sock sockaddr)
	      (\(e :: SomeException) -> sClose sock >> error ("cannot open socket " ++ show sockaddr ++ " " ++ show e))
	dsth <- socketToHandle sock ReadWriteMode
	ctx <- contextNewOnHandle dsth params rng
	f ctx
	hClose dsth

getDefaultParams sStorage session = defaultParams
	{ pConnectVersion    = TLS10
	, pAllowedVersions   = [TLS10,TLS11,TLS12]
	, pCiphers           = ciphers
	, pCertificates      = []
	, pLogging           = logging
	, onCertificatesRecv = crecv
	, onSessionEstablished = \s d -> writeIORef sStorage (s,d)
	, sessionResumeWith  = session
	}
	where
		logging = if not debug then defaultLogging else defaultLogging
			{ loggingPacketSent = putStrLn . ("debug: >> " ++)
			, loggingPacketRecv = putStrLn . ("debug: << " ++)
			}
		crecv = if validateCert then certificateVerifyChain else (\_ -> return CertificateUsageAccept)


main = do
	sStorage <- newIORef undefined
	args     <- getArgs
	let hostname = args !! 0
	let port = read (args !! 1) :: Int
	runTLS (getDefaultParams sStorage Nothing) hostname (fromIntegral port) $ \ctx -> do
		handshake ctx
		sendData ctx $ LC.pack "GET / HTTP/1.0\r\n\r\n"
		d <- recvData' ctx
		bye ctx
		LC.putStrLn d
		return ()
{-
	session <- readIORef sStorage
	runTLS (getDefaultParams sStorage $ Just session) hostname port $ \ctx -> do
		handshake ctx
		sendData ctx $ LC.pack "GET / HTTP/1.0\r\n\r\n"
		d <- recvData ctx
		bye ctx
		LC.putStrLn d
		return ()
-}
