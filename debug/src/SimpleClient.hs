{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
import Network.BSD
import Network.Socket
import Network.TLS
import Network.TLS.Extra
import System.Console.GetOpt
import System.IO
import qualified Crypto.Random.AESCtr as RNG
import qualified Data.ByteString.Lazy.Char8 as LC
import qualified Data.ByteString.Char8 as BC
import Control.Exception
import qualified Control.Exception as E
import Control.Monad
import System.Environment
import System.Exit
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
	() <- f ctx
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

data Flag = Verbose | Session | Http11 | Uri String
          deriving (Show,Eq)

options :: [OptDescr Flag]
options =
    [ Option ['v']  ["verbose"] (NoArg Verbose) "verbose output on stdout"
    , Option ['s']  ["session"] (NoArg Session) "try to resume a session"
    , Option []     ["http1.1"] (NoArg Http11) "use http1.1 instead of http1.0"
    , Option []     ["uri"]     (ReqArg Uri "URI") "optional URI requested by default /"
    ]

runOn (sStorage, certStore) flags port hostname = do
    doTLS Nothing
    when (Session `elem` flags) $ do
        session <- readIORef sStorage
        doTLS (Just session)
    where doTLS sess = do
            let query = LC.pack (
                        "GET "
                        ++ findURI flags
                        ++ (if Http11 `elem` flags then (" HTTP1.1\r\nHost: " ++ hostname) else " HTTP1.0")
                        ++ "\r\n\r\n")
            when (Verbose `elem` flags) (putStrLn "sending query:" >> LC.putStrLn query >> putStrLn "")
            runTLS (getDefaultParams certStore sStorage sess) hostname (fromIntegral port) $ \ctx -> do
                handshake ctx
                sendData ctx $ query
                d <- recvData ctx
                bye ctx
                BC.putStrLn d
                return ()
          findURI []        = "/"
          findURI (Uri u:_) = u
          findURI (_:xs)    = findURI xs

main = do
    args <- getArgs
    let (opts,other,errs) = getOpt Permute options args
    when (not $ null errs) $ do
        putStrLn $ show errs
        exitFailure

    certStore <- getSystemCertificateStore
    sStorage <- newIORef undefined
    case other of
        [hostname]      -> runOn (sStorage, certStore) opts 443 hostname
        [hostname,port] -> runOn (sStorage, certStore) opts (read port) hostname
        _               -> putStrLn "usage: simpleclient [opts] <hostname> [port]" >> exitFailure
