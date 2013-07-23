{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
import Network.BSD
import Network.Socket (socket, socketToHandle, Family(..), SocketType(..), sClose, SockAddr(..), connect)
import Network.TLS
import Network.TLS.Extra
import System.Console.GetOpt
import System.IO
import System.Timeout
import qualified Crypto.Random.AESCtr as RNG
import qualified Data.ByteString.Lazy.Char8 as LC
import qualified Data.ByteString.Char8 as BC
import Control.Exception
import qualified Control.Exception as E
import Control.Monad
import System.Environment
import System.Exit
import System.X509

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

sessionRef ref = SessionManager
    { sessionEstablish  = \sid sdata -> writeIORef ref (sid,sdata)
    , sessionResume     = \sid       -> readIORef ref >>= \(s,d) -> if s == sid then return (Just d) else return Nothing
    , sessionInvalidate = \_         -> return ()
    }

getDefaultParams flags host store sStorage session =
    updateClientParams setCParams $ defaultParamsClient
        { pConnectVersion    = tlsConnectVer
        , pAllowedVersions   = [TLS10,TLS11,TLS12]
        , pCiphers           = ciphers
        , pCertificates      = Nothing
        , pLogging           = logging
        , pSessionManager    = sessionRef sStorage
        , onCertificatesRecv = crecv
        }
    where
            setCParams cparams = cparams
                { clientWantSessionResume = session
                , clientUseServerName = if NoSNI `elem` flags then Nothing else Just host
                }
            logging = if not debug then defaultLogging else defaultLogging
                { loggingPacketSent = putStrLn . ("debug: >> " ++)
                , loggingPacketRecv = putStrLn . ("debug: << " ++)
                }
            checks = defaultChecks (Just host)
            crecv = if validateCert
                        then certificateChecks checks store
                        else certificateNoChecks

            tlsConnectVer
                | Tls12 `elem` flags = TLS12
                | Tls11 `elem` flags = TLS11
                | Ssl3  `elem` flags = SSL3
                | otherwise          = TLS10
            debug = Debug `elem` flags
            validateCert = not (NoValidateCert `elem` flags)

data Flag = Verbose | Debug | NoValidateCert | Session | Http11
          | Ssl3 | Tls11 | Tls12
          | NoSNI
          | Uri String
          | UserAgent String
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
    , Option []     ["no-sni"]  (NoArg NoSNI) "don't use server name indication"
    , Option []     ["user-agent"] (ReqArg UserAgent "user-agent") "use a user agent"
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
                        ++ userAgent
                        ++ "\r\n\r\n")
            when (Verbose `elem` flags) (putStrLn "sending query:" >> LC.putStrLn query >> putStrLn "")
            runTLS (getDefaultParams flags hostname certStore sStorage sess) hostname port $ \ctx -> do
                handshake ctx
                sendData ctx $ query
                loopRecv ctx
                bye ctx
                return ()
          loopRecv ctx = do
            d <- timeout 2000000 (recvData ctx) -- 2s per recv
            case d of
                Nothing            -> when (Debug `elem` flags) (hPutStrLn stderr "timeout") >> return ()
                Just b | BC.null b -> return ()
                       | otherwise -> BC.putStrLn b >> loopRecv ctx

          findURI []        = "/"
          findURI (Uri u:_) = u
          findURI (_:xs)    = findURI xs

          userAgent = maybe "" (\s -> "\r\nUser-Agent: " ++ s) mUserAgent
          mUserAgent = foldl f Nothing flags
            where f _   (UserAgent ua) = Just ua
                  f acc _              = acc

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
        [hostname,port] -> runOn (sStorage, certStore) opts (fromInteger $ read port) hostname
        _               -> printUsage >> exitFailure
