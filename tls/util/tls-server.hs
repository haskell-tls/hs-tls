{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module Main where

import qualified Data.ByteString.Base16 as BS16
import qualified Data.ByteString.Char8 as C8
import Data.IORef
import qualified Data.Map.Strict as M
import Data.X509.CertificateStore
import Network.Run.TCP
import Network.TLS
import Network.TLS.Internal
import System.Console.GetOpt
import System.Environment (getArgs)
import System.Exit
import System.IO
import System.X509

import Common
import Imports
import Server

data Options = Options
    { optDebugLog :: Bool
    , optClientAuth :: Bool
    , optShow :: Bool
    , optKeyLogFile :: Maybe FilePath
    , optTrustedAnchor :: Maybe FilePath
    , optGroups :: [Group]
    , optCertFile :: FilePath
    , optKeyFile :: FilePath
    }
    deriving (Show)

defaultOptions :: Options
defaultOptions =
    Options
        { optDebugLog = False
        , optClientAuth = False
        , optShow = False
        , optKeyLogFile = Nothing
        , optTrustedAnchor = Nothing
        , -- excluding FFDHE8192 for retry
          optGroups = FFDHE8192 `delete` supportedGroups defaultSupported
        , optCertFile = "servercert.pem"
        , optKeyFile = "serverkey.pem"
        }

options :: [OptDescr (Options -> Options)]
options =
    [ Option
        ['a']
        ["client-auth"]
        (NoArg (\o -> o{optClientAuth = True}))
        "require client authentication"
    , Option
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
        "groups for key exchange"
    , Option
        ['c']
        ["cert"]
        (ReqArg (\fl o -> o{optCertFile = fl}) "<file>")
        "certificate file"
    , Option
        ['k']
        ["key"]
        (ReqArg (\fl o -> o{optKeyFile = fl}) "<file>")
        "key file"
    , Option
        ['t']
        ["trusted-anchor"]
        (ReqArg (\fl o -> o{optTrustedAnchor = Just fl}) "<file>")
        "trusted anchor file"
    ]

usage :: String
usage = "Usage: server [OPTION] addr port"

showUsageAndExit :: String -> IO a
showUsageAndExit msg = do
    putStrLn msg
    putStrLn $ usageInfo usage options
    exitFailure

serverOpts :: [String] -> IO (Options, [String])
serverOpts argv =
    case getOpt Permute options argv of
        (o, n, []) -> return (foldl (flip id) defaultOptions o, n)
        (_, _, errs) -> showUsageAndExit $ concat errs

main :: IO ()
main = do
    hSetBuffering stdout NoBuffering
    args <- getArgs
    (Options{..}, ips) <- serverOpts args
    (host, port) <- case ips of
        [h, p] -> return (h, p)
        _ -> showUsageAndExit "cannot recognize <addr> and <port>\n"
    when (null optGroups) $ do
        putStrLn "Error: unsupported groups"
        exitFailure
    smgr <- newSessionManager
    Right cred@(!_cc, !_priv) <- credentialLoadX509 optCertFile optKeyFile
    mstore <-
        if optClientAuth
            then do
                mstore' <- case optTrustedAnchor of
                    Nothing -> Just <$> getSystemCertificateStore
                    Just file -> readCertificateStore file
                when (isNothing mstore') $ showUsageAndExit "cannot set trusted anchor"
                return mstore'
            else return Nothing
    let keyLog = getLogger optKeyLogFile
        creds = Credentials [cred]
    makeCipherShowPretty
    runTCPServer (Just host) port $ \sock -> do
        let sparams = getServerParams creds optGroups smgr keyLog mstore
        ctx <- contextNew sock sparams
        when optDebugLog $
            contextHookSetLogging
                ctx
                defaultLogging
                    { loggingPacketSent = putStrLn . ("<< " ++)
                    , loggingPacketRecv = putStrLn . (">> " ++)
                    }
        when (optDebugLog || optShow) $ putStrLn "------------------------"
        handshake ctx
        when optDebugLog $
            getInfo ctx >>= printHandshakeInfo
        server ctx optShow
        bye ctx

getServerParams
    :: Credentials
    -> [Group]
    -> SessionManager
    -> (String -> IO ())
    -> Maybe CertificateStore
    -> ServerParams
getServerParams creds groups sm keyLog mstore =
    defaultParamsServer
        { serverSupported = supported
        , serverShared = shared
        , serverHooks = hooks
        , serverDebug = debug
        , serverEarlyDataSize = 2048
        , serverWantClientCert = isJust mstore
        }
  where
    shared =
        defaultShared
            { sharedCredentials = creds
            , sharedSessionManager = sm
            , sharedCAStore = case mstore of
                Just store -> store
                Nothing -> sharedCAStore defaultShared
            }
    supported =
        defaultSupported
            { supportedGroups = groups
            }
    hooks =
        defaultServerHooks
            { onALPNClientSuggest = Just chooseALPN
            , onClientCertificate = case mstore of
                Nothing -> onClientCertificate defaultServerHooks
                Just _ ->
                    validateClientCertificate (sharedCAStore shared) (sharedValidationCache shared)
            }
    debug = defaultDebugParams{debugKeyLogger = keyLog}

chooseALPN :: [ByteString] -> IO ByteString
chooseALPN protos
    | "http/1.1" `elem` protos = return "http/1.1"
    | otherwise = return ""

newSessionManager :: IO SessionManager
newSessionManager = do
    ref <- newIORef M.empty
    return $
        noSessionManager
            { sessionResume = \key -> do
                C8.putStrLn $ "sessionResume: " <> BS16.encode key
                M.lookup key <$> readIORef ref
            , sessionResumeOnlyOnce = \key -> do
                C8.putStrLn $ "sessionResumeOnlyOnce: " <> BS16.encode key
                M.lookup key <$> readIORef ref
            , sessionEstablish = \key val -> do
                C8.putStrLn $ "sessionEstablish: " <> BS16.encode key
                atomicModifyIORef' ref $ \m -> (M.insert key val m, Nothing)
            , sessionInvalidate = \key -> do
                C8.putStrLn $ "sessionEstablish: " <> BS16.encode key
                atomicModifyIORef' ref $ \m -> (M.delete key m, ())
            , sessionUseTicket = False
            }
