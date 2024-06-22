{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Concurrent
import qualified Data.ByteString.Char8 as C8
import Data.Default.Class (def)
import Data.IORef
import Data.X509.CertificateStore
import Network.Run.TCP
import Network.Socket
import Network.TLS
import System.Console.GetOpt
import System.Environment
import System.Exit
import System.X509
import qualified UnliftIO.Exception as E

import Client
import Common
import Imports

data Options = Options
    { optDebugLog :: Bool
    , optShow :: Bool
    , optKeyLogFile :: Maybe FilePath
    , optGroups :: [Group]
    , optValidate :: Bool
    , optVerNego :: Bool
    , optResumption :: Bool
    , opt0RTT :: Bool
    , optRetry :: Bool
    , optVersions :: [Version]
    }
    deriving (Show)

defaultOptions :: Options
defaultOptions =
    Options
        { optDebugLog = False
        , optShow = False
        , optKeyLogFile = Nothing
        , optGroups = supportedGroups def
        , optValidate = False
        , optVerNego = False
        , optResumption = False
        , opt0RTT = False
        , optRetry = False
        , optVersions = supportedVersions def
        }

usage :: String
usage = "Usage: quic-client [OPTION] addr port [path]"

options :: [OptDescr (Options -> Options)]
options =
    [ Option
        ['d']
        ["debug"]
        (NoArg (\o -> o{optDebugLog = True}))
        "print debug info"
    , Option
        ['v']
        ["show-content"]
        (NoArg (\o -> o{optShow = True}))
        "print downloaded content"
    , Option
        ['l']
        ["key-log-file"]
        (ReqArg (\file o -> o{optKeyLogFile = Just file}) "<file>")
        "a file to store negotiated secrets"
    , Option
        ['g']
        ["groups"]
        (ReqArg (\gs o -> o{optGroups = readGroups gs}) "<groups>")
        "specify groups"
    , Option
        ['e']
        ["validate"]
        (NoArg (\o -> o{optValidate = True}))
        "validate server's certificate"
    , Option
        ['R']
        ["resumption"]
        (NoArg (\o -> o{optResumption = True}))
        "try session resumption"
    , Option
        ['Z']
        ["0rtt"]
        (NoArg (\o -> o{opt0RTT = True}))
        "try sending early data"
    , Option
        ['S']
        ["hello-retry"]
        (NoArg (\o -> o{optRetry = True}))
        "try client hello retry"
    , Option
        ['2']
        ["tls12"]
        (NoArg (\o -> o{optVersions = [TLS12]}))
        "use TLS 1.2"
    , Option
        ['3']
        ["tls13"]
        (NoArg (\o -> o{optVersions = [TLS13]}))
        "use TLS 1.3"
    ]

showUsageAndExit :: String -> IO a
showUsageAndExit msg = do
    putStrLn msg
    putStrLn $ usageInfo usage options
    putStrLn $ "  <groups> = " ++ (intercalate "," (map fst namedGroups))
    exitFailure

clientOpts :: [String] -> IO (Options, [String])
clientOpts argv =
    case getOpt Permute options argv of
        (o, n, []) -> return (foldl (flip id) defaultOptions o, n)
        (_, _, errs) -> showUsageAndExit $ concat errs

main :: IO ()
main = do
    args <- getArgs
    (opts@Options{..}, ips) <- clientOpts args
    (host, port, paths) <- case ips of
        [] -> showUsageAndExit usage
        _ : [] -> showUsageAndExit usage
        h : p : [] -> return (h, p, ["/"])
        h : p : ps -> return (h, p, C8.pack <$> ps)
    when (null optGroups) $ do
        putStrLn "Error: unsupported groups"
        exitFailure
    ref <- newIORef Nothing
    let debug
            | optDebugLog = putStrLn
            | otherwise = \_ -> return ()
        showContent
            | optShow = C8.putStr
            | otherwise = \_ -> return ()
        aux =
            Aux
                { auxAuthority = host
                , auxPort = port
                , auxDebug = debug
                , auxShow = showContent
                , auxReadResumptionData = readIORef ref
                }
    mstore <-
        if optValidate then Just <$> getSystemCertificateStore else return Nothing
    let keyLog = getLogger optKeyLogFile
        groups
            | optRetry = FFDHE8192 : optGroups
            | otherwise = optGroups
        cparams = getClientParams optVersions host port groups (smIORef ref) mstore keyLog
    runClient opts cparams aux paths

runClient :: Options -> ClientParams -> Aux -> [ByteString] -> IO ()
runClient opts@Options{..} cparams aux@Aux{..} paths = do
    auxDebug "------------------------"
    (info1, msd) <- runTLS cparams aux $ \ctx -> do
        i1 <- getInfo ctx
        when optDebugLog $ printHandshakeInfo i1
        client aux paths ctx
        msd' <- auxReadResumptionData
        return (i1, msd')
    if
        | optResumption ->
            if isResumptionPossible msd
                then do
                    let cparams2 = modifyClientParams cparams msd False
                    info2 <- runClient2 opts cparams2 aux paths
                    if infoVersion info1 == TLS12
                        then do
                            if infoTLS12Resumption info2
                                then do
                                    putStrLn "Result: (R) TLS resumption ... OK"
                                    exitSuccess
                                else do
                                    putStrLn "Result: (R) TLS resumption ... NG"
                                    exitFailure
                        else do
                            if infoTLS13HandshakeMode info2 == Just PreSharedKey
                                then do
                                    putStrLn "Result: (R) TLS resumption ... OK"
                                    exitSuccess
                                else do
                                    putStrLn "Result: (R) TLS resumption ... NG"
                                    exitFailure
                else do
                    putStrLn "Result: (R) TLS resumption ... NG"
                    exitFailure
        | opt0RTT ->
            if is0RTTPossible info1 msd
                then do
                    let cparams2 = modifyClientParams cparams msd True
                    info2 <- runClient2 opts cparams2 aux paths
                    if infoTLS13HandshakeMode info2 == Just RTT0
                        then do
                            putStrLn "Result: (Z) 0-RTT ... OK"
                            exitSuccess
                        else do
                            putStrLn "Result: (Z) 0-RTT ... NG"
                            exitFailure
                else do
                    putStrLn "Result: (Z) 0-RTT ... NG"
                    exitFailure
        | optRetry ->
            if infoTLS13HandshakeMode info1 == Just HelloRetryRequest
                then do
                    putStrLn "Result: (S) retry ... OK"
                    exitSuccess
                else do
                    putStrLn "Result: (S) retry ... NG"
                    exitFailure
        | otherwise -> do
            putStrLn "Result: (H) handshake ... OK"
            let malpn = (snd <$> msd) >>= sessionALPN
            when (malpn == Just "http/1.1") $
                putStrLn "Result: (1) HTTP/1.1 transaction ... OK"
            exitSuccess

runClient2
    :: Options
    -> ClientParams
    -> Aux
    -> [ByteString]
    -> IO Information
runClient2 Options{..} cparams aux@Aux{..} paths = do
    threadDelay 100000
    auxDebug "<<<< next connection >>>>"
    auxDebug "------------------------"
    runTLS cparams aux $ \ctx -> do
        if opt0RTT
            then do
                void $ client aux paths ctx
                i <- getInfo ctx
                when optDebugLog $ printHandshakeInfo i
                return i
            else do
                i <- getInfo ctx
                when optDebugLog $ printHandshakeInfo i
                void $ client aux paths ctx
                return i

runTLS
    :: ClientParams
    -> Aux
    -> (Context -> IO a)
    -> IO a
runTLS cparams Aux{..} action =
    runTCPClient auxAuthority auxPort $ \sock -> do
        E.bracket (contextNew sock cparams) bye $ \ctx -> do
            handshake ctx
            action ctx

modifyClientParams
    :: ClientParams -> Maybe (SessionID, SessionData) -> Bool -> ClientParams
modifyClientParams cparams wantResume early =
    cparams
        { clientWantSessionResume = wantResume
        , clientUseEarlyData = early
        }

getClientParams
    :: [Version]
    -> HostName
    -> ServiceName
    -> [Group]
    -> SessionManager
    -> Maybe CertificateStore
    -> (String -> IO ())
    -> ClientParams
getClientParams vers serverName port groups sm mstore keyLog =
    (defaultParamsClient serverName (C8.pack port))
        { clientSupported = supported
        , clientUseServerNameIndication = True
        , clientShared = shared
        , clientHooks = hooks
        , clientDebug = debug
        }
  where
    shared =
        def
            { sharedSessionManager = sm
            , sharedCAStore = case mstore of
                Just store -> store
                Nothing -> mempty
            , sharedValidationCache = validateCache
            }
    supported =
        def
            { supportedVersions = vers
            , supportedGroups = groups
            }
    hooks =
        def
            { onSuggestALPN = return $ Just ["http/1.1"]
            , onServerFinished = print
            }
    validateCache
        | isJust mstore = def
        | otherwise =
            ValidationCache
                (\_ _ _ -> return ValidationCachePass)
                (\_ _ _ -> return ())
    debug =
        def
            { debugKeyLogger = keyLog
            }

smIORef :: IORef (Maybe (SessionID, SessionData)) -> SessionManager
smIORef ref =
    noSessionManager
        { sessionEstablish = \sid sdata -> writeIORef ref (Just (sid, sdata)) >> return Nothing
        }

isResumptionPossible :: Maybe (SessionID, SessionData) -> Bool
isResumptionPossible = isJust

is0RTTPossible :: Information -> Maybe (SessionID, SessionData) -> Bool
is0RTTPossible _ Nothing = False
is0RTTPossible info (Just (_, sd)) =
    infoVersion info == TLS13
        && sessionMaxEarlyDataSize sd > 0
