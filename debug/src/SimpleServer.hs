{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
import Crypto.Random
import Network.BSD
import Network.Socket (socket, Family(..), SocketType(..), sClose, SockAddr(..), bind, listen, accept)
import Network.TLS
import Network.TLS.Extra.Cipher
import System.Console.GetOpt
import System.IO
import System.Timeout
import qualified Data.ByteString.Lazy.Char8 as LC
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString as B
import Control.Exception
import qualified Control.Exception as E
import Control.Monad
import System.Environment
import System.Exit
import System.X509
import Data.X509.CertificateStore

import Data.Default.Class
import Data.IORef
import Data.Monoid
import Data.Char (isDigit)
import Data.X509.Validation

import Numeric (showHex)

import HexDump

ciphers :: [Cipher]
ciphers =
    [ cipher_DHE_RSA_AES256_SHA256
    , cipher_DHE_RSA_AES128_SHA256
    , cipher_DHE_RSA_AES256_SHA1
    , cipher_DHE_RSA_AES128_SHA1
    , cipher_DHE_DSS_AES256_SHA1
    , cipher_DHE_DSS_AES128_SHA1
    , cipher_AES128_SHA1
    , cipher_AES256_SHA1
    , cipher_RC4_128_MD5
    , cipher_RC4_128_SHA1
    , cipher_RSA_3DES_EDE_CBC_SHA1
    , cipher_DHE_RSA_AES128GCM_SHA256
    ]

defaultBenchAmount = 1024 * 1024
defaultTimeout = 2000

bogusCipher cid = cipher_AES128_SHA1 { cipherID = cid }

runTLS debug ioDebug params hostname portNumber f = do
    he   <- getHostByName hostname
    sock <- socket AF_INET Stream defaultProtocol
    let sockaddr = SockAddrInet portNumber (head $ hostAddresses he)

    bind sock sockaddr
    listen sock 1
    (cSock, cAddr) <- accept sock

    putStrLn ("connection from " ++ show cAddr)

    ctx <- contextNew cSock params
    contextHookSetLogging ctx getLogging
    () <- f ctx
    sClose cSock
    sClose sock
  where getLogging = ioLogging $ packetLogging $ def
        packetLogging logging
            | debug = logging { loggingPacketSent = putStrLn . ("debug: >> " ++)
                              , loggingPacketRecv = putStrLn . ("debug: << " ++)
                              }
            | otherwise = logging
        ioLogging logging
            | ioDebug = logging { loggingIOSent = mapM_ putStrLn . hexdump ">>"
                                , loggingIORecv = \hdr body -> do
                                    putStrLn ("<< " ++ show hdr)
                                    mapM_ putStrLn $ hexdump "<<" body
                                }
            | otherwise = logging

sessionRef ref = SessionManager
    { sessionEstablish  = \sid sdata -> writeIORef ref (sid,sdata)
    , sessionResume     = \sid       -> readIORef ref >>= \(s,d) -> if s == sid then return (Just d) else return Nothing
    , sessionInvalidate = \_         -> return ()
    }

getDefaultParams :: [Flag] -> String -> CertificateStore -> IORef (SessionID, SessionData) -> Credential -> Maybe (SessionID, SessionData) -> ServerParams
getDefaultParams flags host store sStorage cred session =
    ServerParams
        { serverWantClientCert = False
        , serverCACertificates = []
        , serverDHEParams = Nothing
        , serverShared = def { sharedSessionManager  = sessionRef sStorage
                             , sharedCAStore         = store
                             , sharedValidationCache = validateCache
                             , sharedCredentials     = Credentials [cred]
                             }
        , serverHooks = def
        , serverSupported = def { supportedVersions = supportedVers, supportedCiphers = myCiphers }
        , serverDebug = def { debugSeed      = foldl getDebugSeed Nothing flags
                            , debugPrintSeed = if DebugPrintSeed `elem` flags
                                                    then (\seed -> putStrLn ("seed: " ++ show (seedToInteger seed)))
                                                    else (\_ -> return ())
                            }
        }
    where
            validateCache
                | validateCert = def
                | otherwise    = ValidationCache (\_ _ _ -> return ValidationCachePass)
                                                 (\_ _ _ -> return ())

            myCiphers = foldl accBogusCipher (filter withUseCipher ciphers) flags
              where accBogusCipher acc (BogusCipher c) =
                        case reads c of
                            [(v, "")] -> acc ++ [bogusCipher v]
                            _         -> acc
                    accBogusCipher acc _ = acc

            getUsedCiphers = foldl f [] flags
              where f acc (UseCipher am) = case readNumber am of
                                                Nothing -> acc
                                                Just i  -> i : acc
                    f acc _ = acc

            withUseCipher c =
                case getUsedCiphers of
                    [] -> True
                    l  -> cipherID c `elem` l

            getDebugSeed :: Maybe Seed -> Flag -> Maybe Seed
            getDebugSeed _   (DebugSeed seed) = seedFromInteger <$> readNumber seed
            getDebugSeed acc _                = acc

            tlsConnectVer
                | Tls12 `elem` flags = TLS12
                | Tls11 `elem` flags = TLS11
                | Ssl3  `elem` flags = SSL3
                | Tls10 `elem` flags = TLS10
                | otherwise          = TLS12
            supportedVers
                | NoVersionDowngrade `elem` flags = [tlsConnectVer]
                | otherwise = filter (<= tlsConnectVer) allVers
            allVers = [SSL3, TLS10, TLS11, TLS12]
            validateCert = not (NoValidateCert `elem` flags)

data Flag = Verbose | Debug | IODebug | NoValidateCert | Session | Http11
          | Ssl3 | Tls10 | Tls11 | Tls12
          | NoSNI
          | NoVersionDowngrade
          | Output String
          | Timeout String
          | BogusCipher String
          | BenchSend
          | BenchRecv
          | BenchData String
          | UseCipher String
          | ListCiphers
          | Certificate String
          | Key String
          | DebugSeed String
          | DebugPrintSeed
          | Help
          deriving (Show,Eq)

options :: [OptDescr Flag]
options =
    [ Option ['v']  ["verbose"] (NoArg Verbose) "verbose output on stdout"
    , Option ['d']  ["debug"]   (NoArg Debug) "TLS debug output on stdout"
    , Option []     ["io-debug"] (NoArg IODebug) "TLS IO debug output on stdout"
    , Option ['s']  ["session"] (NoArg Session) "try to resume a session"
    , Option ['O']  ["output"]  (ReqArg Output "stdout") "output "
    , Option ['t']  ["timeout"] (ReqArg Timeout "timeout") "timeout in milliseconds (2s by default)"
    , Option []     ["no-validation"] (NoArg NoValidateCert) "disable certificate validation"
    , Option []     ["http1.1"] (NoArg Http11) "use http1.1 instead of http1.0"
    , Option []     ["ssl3"]    (NoArg Ssl3) "use SSL 3.0"
    , Option []     ["no-sni"]  (NoArg NoSNI) "don't use server name indication"
    , Option []     ["tls10"]   (NoArg Tls10) "use TLS 1.0"
    , Option []     ["tls11"]   (NoArg Tls11) "use TLS 1.1"
    , Option []     ["tls12"]   (NoArg Tls12) "use TLS 1.2 (default)"
    , Option []     ["bogocipher"] (ReqArg BogusCipher "cipher-id") "add a bogus cipher id for testing"
    , Option ['x']  ["no-version-downgrade"] (NoArg NoVersionDowngrade) "do not allow version downgrade"
    , Option ['h']  ["help"]    (NoArg Help) "request help"
    , Option []     ["bench-send"]   (NoArg BenchSend) "benchmark send path. only with compatible server"
    , Option []     ["bench-recv"]   (NoArg BenchRecv) "benchmark recv path. only with compatible server"
    , Option []     ["bench-data"] (ReqArg BenchData "amount") "amount of data to benchmark with"
    , Option []     ["use-cipher"] (ReqArg UseCipher "cipher-id") "use a specific cipher" 
    , Option []     ["list-ciphers"] (NoArg ListCiphers) "list all ciphers supported and exit"
    , Option []     ["certificate"] (ReqArg Certificate "certificate") "certificate file"
    , Option []     ["debug-seed"] (ReqArg DebugSeed "debug-seed") "debug: set a specific seed for randomness"
    , Option []     ["debug-print-seed"] (NoArg DebugPrintSeed) "debug: set a specific seed for randomness"
    , Option []     ["key"] (ReqArg Key "key") "certificate file"
    ]

noSession = Nothing

loadCred (Just key) (Just cert) = do
    res <- credentialLoadX509 cert key
    case res of
        Left err -> error ("cannot load certificate: " ++ err)
        Right v  -> return v
loadCred Nothing _ =
    error "missing credential key"
loadCred _       Nothing =
    error "missing credential certificate"

runOn (sStorage, certStore) flags port hostname
    | BenchSend `elem` flags = runBench True
    | BenchRecv `elem` flags = runBench False
    | otherwise              = do
        --certCredRequest <- getCredRequest
        doTLS noSession
        when (Session `elem` flags) $ do
            session <- readIORef sStorage
            doTLS (Just session)
  where
        runBench isSend = do
            cred <- loadCred getKey getCertificate
            runTLS False False
                   (getDefaultParams flags hostname certStore sStorage cred noSession) hostname port $ \ctx -> do
                handshake ctx
                if isSend
                    then loopSendData getBenchAmount ctx
                    else loopRecvData getBenchAmount ctx
                bye ctx
          where
            dataSend = BC.replicate 4096 'a'
            loopSendData bytes ctx
                | bytes <= 0 = return ()
                | otherwise  = do
                    sendData ctx $ LC.fromChunks [(if bytes > B.length dataSend then dataSend else BC.take bytes dataSend)]
                    loopSendData (bytes - B.length dataSend) ctx

            loopRecvData bytes ctx
                | bytes <= 0 = return ()
                | otherwise  = do
                    d <- recvData ctx
                    loopRecvData (bytes - B.length d) ctx

        doTLS sess = do
            out <- maybe (return stdout) (flip openFile WriteMode) getOutput

            cred <- loadCred getKey getCertificate

            runTLS (Debug `elem` flags)
                   (IODebug `elem` flags)
                   (getDefaultParams flags hostname certStore sStorage cred sess) hostname port $ \ctx -> do
                handshake ctx
                loopRecv out ctx
                --sendData ctx $ query
                bye ctx
                return ()
        loopRecv out ctx = do
            d <- timeout (timeoutMs * 1000) (recvData ctx) -- 2s per recv
            case d of
                Nothing            -> when (Debug `elem` flags) (hPutStrLn stderr "timeout") >> return ()
                Just b | BC.null b -> return ()
                       | otherwise -> BC.hPutStrLn out b >> loopRecv out ctx

{-
        getCredRequest =
            case clientCert of
                Nothing -> return Nothing
                Just s  -> do
                    case break (== ':') s of
                        (_   ,"")      -> error "wrong format for client-cert, expecting 'cert-file:key-file'"
                        (cert,':':key) -> do
                            ecred <- credentialLoadX509 cert key
                            case ecred of
                                Left err   -> error ("cannot load client certificate: " ++ err)
                                Right cred -> do
                                    let certRequest _ = return $ Just cred
                                    return $ Just (Credentials [cred], certRequest)
                        (_   ,_)      -> error "wrong format for client-cert, expecting 'cert-file:key-file'"
-}

        getOutput = foldl f Nothing flags
          where f _   (Output o) = Just o
                f acc _          = acc
        timeoutMs = foldl f defaultTimeout flags
          where f _   (Timeout t) = read t
                f acc _           = acc
        getKey = foldl f Nothing flags
          where f _   (Key key) = Just key
                f acc _         = acc
        getCertificate = foldl f Nothing flags
          where f _   (Certificate cert) = Just cert
                f acc _                  = acc
        getBenchAmount = foldl f defaultBenchAmount flags
          where f acc (BenchData am) = case readNumber am of
                                            Nothing -> acc
                                            Just i  -> i
                f acc _              = acc

readNumber :: (Num a, Read a) => String -> Maybe a
readNumber s
    | all isDigit s = Just $ read s
    | otherwise     = Nothing

printUsage =
    putStrLn $ usageInfo "usage: simpleclient [opts] <hostname> [port]\n\n\t(port default to: 443)\noptions:\n" options

printCiphers = do
    putStrLn "Supported ciphers"
    putStrLn "====================================="
    forM_ ciphers $ \c -> do
        putStrLn (pad 50 (cipherName c) ++ " = " ++ pad 5 (show $ cipherID c) ++ "  0x" ++ showHex (cipherID c) "")
  where
    pad n s
        | length s < n = s ++ replicate (n - length s) ' '
        | otherwise    = s

main = do
    args <- getArgs
    let (opts,other,errs) = getOpt Permute options args
    when (not $ null errs) $ do
        putStrLn $ show errs
        exitFailure

    when (Help `elem` opts) $ do
        printUsage
        exitSuccess

    when (ListCiphers `elem` opts) $ do
        printCiphers
        exitSuccess

    certStore <- getSystemCertificateStore
    sStorage  <- newIORef (error "storage ioref undefined")
    case other of
        [hostname]      -> runOn (sStorage, certStore) opts 443 hostname
        [hostname,port] -> runOn (sStorage, certStore) opts (fromInteger $ read port) hostname
        _               -> printUsage >> exitFailure
