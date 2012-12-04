{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
import Network.BSD
import Network.Socket (socket, socketToHandle, Family(..), SocketType(..), sClose, SockAddr(..), connect)
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

getDefaultParams flags store sStorage session =
    updateClientParams setCParams $ setSessionManager (SessionRef sStorage) $ defaultParamsClient
        { pConnectVersion    = tlsConnectVer
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

            tlsConnectVer
                | Tls12 `elem` flags = TLS12
                | Tls11 `elem` flags = TLS11
                | Ssl3  `elem` flags = SSL3
                | otherwise          = TLS10
            debug = Debug `elem` flags
            validateCert = not (NoValidateCert `elem` flags)

data Flag = Verbose | Debug | NoValidateCert | Session | Http11
          | Ssl3 | Tls11 | Tls12
          | Uri String
          | Help
          deriving (Show,Eq)

options :: [OptDescr Flag]
options =
    [ Option ['v']  ["verbose"] (NoArg Verbose) "verbose output on stdout"
    , Option ['d']  ["debug"]   (NoArg Debug) "TLS debug output on stdout"
    , Option ['s']  ["session"] (NoArg Session) "try to resume a session"
    , Option []     ["no-validation"] (NoArg NoValidateCert) "disable certificate validation"
    , Option []     ["http1.1"] (NoArg Http11) "use http1.1 instead of http1.0"
    , Option []     ["ssl3"]    (NoArg Ssl3) "use SSL 3.0 as default"
    , Option []     ["tls11"]   (NoArg Tls11) "use TLS 1.1 as default"
    , Option []     ["tls12"]   (NoArg Tls12) "use TLS 1.2 as default"
    , Option []     ["uri"]     (ReqArg Uri "URI") "optional URI requested by default /"
    , Option ['h']  ["help"]    (NoArg Help) "request help"
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
                        ++ (if Http11 `elem` flags then (" HTTP/1.1\r\nHost: " ++ hostname) else " HTTP/1.0")
                        ++ "\r\n\r\n")
            when (Verbose `elem` flags) (putStrLn "sending query:" >> LC.putStrLn query >> putStrLn "")
            runTLS (getDefaultParams flags certStore sStorage sess) hostname (fromIntegral port) $ \ctx -> do
                handshake ctx
                sendData ctx $ query
                d <- recvData ctx
                bye ctx
                BC.putStrLn d
                return ()
          findURI []        = "/"
          findURI (Uri u:_) = u
          findURI (_:xs)    = findURI xs

printUsage =
    putStrLn $ usageInfo "usage: simpleclient [opts] <hostname> [port]\n\n\t(port default to: 443)\noptions:\n" options

main = do
    args <- getArgs
    let (opts,other,errs) = getOpt Permute options args
    when (not $ null errs) $ do
        putStrLn $ show errs
        exitFailure

    when (Help `elem` opts) $ do
        printUsage
        exitSuccess

    certStore <- getSystemCertificateStore
    sStorage <- newIORef undefined
    case other of
        [hostname]      -> runOn (sStorage, certStore) opts 443 hostname
        [hostname,port] -> runOn (sStorage, certStore) opts (read port) hostname
        _               -> printUsage >> exitFailure
