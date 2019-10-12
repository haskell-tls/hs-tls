{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-warnings-deprecations #-}

import Control.Exception (SomeException(..))
import qualified Control.Exception as E
import Crypto.Random
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy.Char8 as LC
import Data.Default.Class
import Data.IORef
import Network.Socket (socket, close, connect)
import System.Console.GetOpt
import System.Environment
import System.Exit
import System.IO
import System.Timeout

import Network.TLS
import Network.TLS.Extra.Cipher

import Common
import HexDump
import Imports

defaultBenchAmount = 1024 * 1024
defaultTimeout = 2000

bogusCipher cid = cipher_AES128_SHA1 { cipherID = cid }

runTLS debug ioDebug params hostname portNumber f =
    E.bracket setup teardown $ \sock -> do
        ctx <- contextNew sock params
        contextHookSetLogging ctx getLogging
        f ctx
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
        setup = do
            ai <- makeAddrInfo (Just hostname) portNumber
            sock <- socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai)
            let sockaddr = addrAddress ai
            connect sock sockaddr
            return sock
        teardown sock = close sock

sessionRef ref = SessionManager
    { sessionEstablish      = \sid sdata -> writeIORef ref (sid,sdata)
    , sessionResume         = \sid       -> readIORef ref >>= \(s,d) -> if s == sid then return (Just d) else return Nothing
    , sessionResumeOnlyOnce = \_         -> fail "sessionResumeOnlyOnce not implemented for simple client"
    , sessionInvalidate     = \_         -> return ()
    }

getDefaultParams flags host store sStorage certCredsRequest session earlyData =
    (defaultParamsClient serverName BC.empty)
        { clientSupported = def { supportedVersions = supportedVers
                                , supportedCiphers = myCiphers
                                , supportedGroups = getGroups flags
                                }
        , clientWantSessionResume = session
        , clientUseServerNameIndication = NoSNI `notElem` flags
        , clientShared = def { sharedSessionManager  = sessionRef sStorage
                             , sharedCAStore         = store
                             , sharedValidationCache = validateCache
                             }
        , clientHooks = def { onCertificateRequest = fromMaybe (onCertificateRequest def) certCredsRequest }
        , clientDebug = def { debugSeed      = foldl getDebugSeed Nothing flags
                            , debugPrintSeed = if DebugPrintSeed `elem` flags
                                                    then (\seed -> putStrLn ("seed: " ++ show (seedToInteger seed)))
                                                    else (\_ -> return ())
                            }
        , clientEarlyData = earlyData
        }
    where
            serverName = foldl f host flags
              where f _   (SNI n) = n
                    f acc _       = acc

            validateCache
                | validateCert = def
                | otherwise    = ValidationCache (\_ _ _ -> return ValidationCachePass)
                                                 (\_ _ _ -> return ())
            myCiphers = foldl accBogusCipher getSelectedCiphers flags
              where accBogusCipher acc (BogusCipher c) =
                        case reads c of
                            [(v, "")] -> acc ++ [bogusCipher v]
                            _         -> acc
                    accBogusCipher acc _ = acc

            getUsedCipherIDs = foldl f [] flags
              where f acc (UseCipher am) =
                            case readCiphers am of
                                Just l  -> l ++ acc
                                Nothing -> acc
                    f acc _ = acc

            getSelectedCiphers =
                case getUsedCipherIDs of
                    [] -> ciphersuite_all
                    l  -> mapMaybe (\cid -> find ((== cid) . cipherID) ciphersuite_all) l

            getDebugSeed :: Maybe Seed -> Flag -> Maybe Seed
            getDebugSeed _   (DebugSeed seed) = seedFromInteger `fmap` readNumber seed
            getDebugSeed acc _                = acc

            tlsConnectVer
                | Tls13 `elem` flags = TLS13
                | Tls12 `elem` flags = TLS12
                | Tls11 `elem` flags = TLS11
                | Ssl3  `elem` flags = SSL3
                | Tls10 `elem` flags = TLS10
                | otherwise          = TLS13
            supportedVers
                | NoVersionDowngrade `elem` flags = [tlsConnectVer]
                | otherwise = filter (<= tlsConnectVer) allVers
            allVers = [TLS13, TLS12, TLS11, TLS10, SSL3]
            validateCert = not (NoValidateCert `elem` flags)

getGroups flags = case getGroup >>= readGroups of
    Nothing     -> defaultGroups
    Just []     -> defaultGroups
    Just groups -> groups
  where
    defaultGroups = supportedGroups def
    getGroup = foldl f Nothing flags
      where f _   (Group g)  = Just g
            f acc _          = acc

data Flag = Verbose | Debug | IODebug | NoValidateCert | Session | Http11
          | Ssl3 | Tls10 | Tls11 | Tls12 | Tls13
          | SNI String
          | NoSNI
          | Uri String
          | NoVersionDowngrade
          | UserAgent String
          | Input String
          | Output String
          | Timeout String
          | BogusCipher String
          | ClientCert String
          | TrustAnchor String
          | BenchSend
          | BenchRecv
          | BenchData String
          | UseCipher String
          | ListCiphers
          | ListGroups
          | DebugSeed String
          | DebugPrintSeed
          | Group String
          | Help
          | UpdateKey
          deriving (Show,Eq)

options :: [OptDescr Flag]
options =
    [ Option ['v']  ["verbose"] (NoArg Verbose) "verbose output on stdout"
    , Option ['d']  ["debug"]   (NoArg Debug) "TLS debug output on stdout"
    , Option []     ["io-debug"] (NoArg IODebug) "TLS IO debug output on stdout"
    , Option ['s']  ["session"] (NoArg Session) "try to resume a session"
    , Option ['Z']  ["zerortt"]  (ReqArg Input "inpfile") "input for TLS 1.3 0RTT data"
    , Option ['O']  ["output"]  (ReqArg Output "stdout") "output "
    , Option ['g']  ["group"]  (ReqArg Group "group") "group"
    , Option ['t']  ["timeout"] (ReqArg Timeout "timeout") "timeout in milliseconds (2s by default)"
    , Option ['u']  ["update-key"]   (NoArg UpdateKey) "Updating keys after sending the first request then sending the same request again (TLS 1.3 only)"
    , Option []     ["no-validation"] (NoArg NoValidateCert) "disable certificate validation"
    , Option []     ["client-cert"] (ReqArg ClientCert "cert-file:key-file") "add a client certificate to use with the server"
    , Option []     ["trust-anchor"] (ReqArg TrustAnchor "pem-or-dir") "use provided CAs instead of system certificate store"
    , Option []     ["http1.1"] (NoArg Http11) "use http1.1 instead of http1.0"
    , Option []     ["ssl3"]    (NoArg Ssl3) "use SSL 3.0"
    , Option []     ["sni"]     (ReqArg SNI "server-name") "use non-default server name indication"
    , Option []     ["no-sni"]  (NoArg NoSNI) "don't use server name indication"
    , Option []     ["user-agent"] (ReqArg UserAgent "user-agent") "use a user agent"
    , Option []     ["tls10"]   (NoArg Tls10) "use TLS 1.0"
    , Option []     ["tls11"]   (NoArg Tls11) "use TLS 1.1"
    , Option []     ["tls12"]   (NoArg Tls12) "use TLS 1.2"
    , Option []     ["tls13"]   (NoArg Tls13) "use TLS 1.3 (default)"
    , Option []     ["bogocipher"] (ReqArg BogusCipher "cipher-id") "add a bogus cipher id for testing"
    , Option ['x']  ["no-version-downgrade"] (NoArg NoVersionDowngrade) "do not allow version downgrade"
    , Option []     ["uri"]     (ReqArg Uri "URI") "optional URI requested by default /"
    , Option ['h']  ["help"]    (NoArg Help) "request help"
    , Option []     ["bench-send"]   (NoArg BenchSend) "benchmark send path. only with compatible server"
    , Option []     ["bench-recv"]   (NoArg BenchRecv) "benchmark recv path. only with compatible server"
    , Option []     ["bench-data"] (ReqArg BenchData "amount") "amount of data to benchmark with"
    , Option []     ["use-cipher"] (ReqArg UseCipher "cipher-id") "use a specific cipher"
    , Option []     ["list-ciphers"] (NoArg ListCiphers) "list all ciphers supported and exit"
    , Option []     ["list-groups"] (NoArg ListGroups) "list all groups supported and exit"
    , Option []     ["debug-seed"] (ReqArg DebugSeed "debug-seed") "debug: set a specific seed for randomness"
    , Option []     ["debug-print-seed"] (NoArg DebugPrintSeed) "debug: set a specific seed for randomness"
    ]

noSession = Nothing

runOn (sStorage, certStore) flags port hostname
    | BenchSend `elem` flags = runBench True
    | BenchRecv `elem` flags = runBench False
    | otherwise              = do
        certCredRequest <- getCredRequest
        doTLS certCredRequest noSession Nothing `E.catch` \(SomeException e) -> print e
        when (Session `elem` flags) $ do
            putStrLn "\nResuming the session..."
            session <- readIORef sStorage
            earlyData <- case getInput of
              Nothing -> return Nothing
              Just i  -> Just <$> B.readFile i
            doTLS certCredRequest (Just session) earlyData `E.catch` \(SomeException e) -> print e
  where
        runBench isSend =
            runTLS (Debug `elem` flags)
                   (IODebug `elem` flags)
                   (getDefaultParams flags hostname certStore sStorage Nothing noSession Nothing) hostname port $ \ctx -> do
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

        doTLS certCredRequest sess earlyData = E.bracket setup teardown $ \out -> do
            let query = LC.pack (
                        "GET "
                        ++ findURI flags
                        ++ (if Http11 `elem` flags then (" HTTP/1.1\r\nHost: " ++ hostname) else " HTTP/1.0")
                        ++ userAgent
                        ++ "\r\n\r\n")
            when (Verbose `elem` flags) (putStrLn "sending query:" >> LC.putStrLn query >> putStrLn "")
            runTLS (Debug `elem` flags)
                   (IODebug `elem` flags)
                   (getDefaultParams flags hostname certStore sStorage certCredRequest sess earlyData) hostname port $ \ctx -> do
                handshake ctx
                when (Verbose `elem` flags) $ printHandshakeInfo ctx
                case earlyData of
                    Just edata -> do
                        minfo <- contextGetInformation ctx
                        case minfo of
                            Nothing -> return () -- what should we do?
                            Just info -> unless (infoIsEarlyDataAccepted info) $ do
                                putStrLn "Resending 0RTT data ..."
                                sendData ctx $ LC.fromStrict edata
                    _ -> return ()
                sendData ctx $ query
                loopRecv out ctx
                when (UpdateKey `elem` flags) $ do
                    _tls13 <- updateKey ctx TwoWay
                    sendData ctx $ query
                    loopRecv out ctx
                bye ctx `E.catch` \(SomeException e) -> putStrLn $ "bye failed: " ++ show e
                return ()
        setup = maybe (return stdout) (flip openFile AppendMode) getOutput
        teardown out = when (isJust getOutput) $ hClose out
        loopRecv out ctx = do
            d <- timeout (timeoutMs * 1000) (recvData ctx) -- 2s per recv
            case d of
                Nothing            -> when (Debug `elem` flags) (hPutStrLn stderr "timeout") >> return ()
                Just b | BC.null b -> return ()
                       | otherwise -> BC.hPutStrLn out b >> loopRecv out ctx

        getCredRequest =
            case clientCert of
                Nothing -> return Nothing
                Just s  ->
                    case break (== ':') s of
                        (_   ,"")      -> error "wrong format for client-cert, expecting 'cert-file:key-file'"
                        (cert,':':key) -> do
                            ecred <- credentialLoadX509 cert key
                            case ecred of
                                Left err   -> error ("cannot load client certificate: " ++ err)
                                Right cred -> do
                                    let certRequest _ = return $ Just cred
                                    return $ Just certRequest
                        (_   ,_)      -> error "wrong format for client-cert, expecting 'cert-file:key-file'"

        findURI []        = "/"
        findURI (Uri u:_) = u
        findURI (_:xs)    = findURI xs

        userAgent = maybe "" (\s -> "\r\nUser-Agent: " ++ s) mUserAgent
        mUserAgent = foldl f Nothing flags
          where f _   (UserAgent ua) = Just ua
                f acc _              = acc
        getInput = foldl f Nothing flags
          where f _   (Input i)  = Just i
                f acc _          = acc
        getOutput = foldl f Nothing flags
          where f _   (Output o) = Just o
                f acc _          = acc
        timeoutMs = foldl f defaultTimeout flags
          where f _   (Timeout t) = read t
                f acc _           = acc
        clientCert = foldl f Nothing flags
          where f _   (ClientCert c) = Just c
                f acc _              = acc
        getBenchAmount = foldl f defaultBenchAmount flags
          where f acc (BenchData am) = case readNumber am of
                                            Nothing -> acc
                                            Just i  -> i
                f acc _              = acc

getTrustAnchors flags = getCertificateStore (foldr getPaths [] flags)
  where getPaths (TrustAnchor path) acc = path : acc
        getPaths _                  acc = acc

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

    when (ListCiphers `elem` opts) $ do
        printCiphers
        exitSuccess

    when (ListGroups `elem` opts) $ do
        printGroups
        exitSuccess

    certStore <- getTrustAnchors opts
    sStorage <- newIORef (error "storage ioref undefined")
    case other of
        [hostname]      -> runOn (sStorage, certStore) opts 443 hostname
        [hostname,port] -> runOn (sStorage, certStore) opts (fromInteger $ read port) hostname
        _               -> printUsage >> exitFailure
