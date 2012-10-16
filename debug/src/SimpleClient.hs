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
import qualified Control.Exception as E
import System.Environment
import System.Certificate.X509

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
	E.catch (connect sock sockaddr)
	      (\(e :: SomeException) -> sClose sock >> error ("cannot open socket " ++ show sockaddr ++ " " ++ show e))
	dsth <- socketToHandle sock ReadWriteMode
	ctx <- contextNewOnHandle dsth params rng
	f ctx
	hClose dsth

data SessionRef = SessionRef (IORef (SessionID, SessionData))

instance SessionManager SessionRef where
    sessionEstablish (SessionRef ref) sid sdata = writeIORef ref (sid,sdata)
    sessionResume (SessionRef ref) sid = readIORef ref >>= \(s,d) -> if s == sid then return (Just d) else return Nothing
    sessionInvalidate _ _ = return ()

getDefaultParams store sStorage session = updateClientParams setCParams $ setSessionManager (SessionRef sStorage) $ defaultParamsClient
	{ pConnectVersion    = TLS10
	, pAllowedVersions   = [TLS10,TLS11,TLS12]
	, pCiphers           = ciphers
	, pCertificates      = []
	, pLogging           = logging
	, onCertificatesRecv = crecv
	}
	where
		setCParams cparams = cparams { clientWantSessionResume = session }
		logging = if not debug then defaultLogging else defaultLogging
			{ loggingPacketSent = putStrLn . ("debug: >> " ++)
			, loggingPacketRecv = putStrLn . ("debug: << " ++)
			}
		crecv = if validateCert then certificateVerifyChain store else (\_ -> return CertificateUsageAccept)


main = do
	sStorage <- newIORef undefined
	args     <- getArgs
	let hostname = args !! 0
	let port = read (args !! 1) :: Int
	store <- getSystemCertificateStore
	runTLS (getDefaultParams store sStorage Nothing) hostname (fromIntegral port) $ \ctx -> do
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
