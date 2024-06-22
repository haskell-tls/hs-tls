{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module Main where

import qualified Data.ByteString.Base16 as BS16
import qualified Data.ByteString.Char8 as C8
import Data.Default.Class (def)
import Data.IORef
import qualified Data.Map.Strict as M
import Network.Run.TCP
import Network.TLS
import System.Console.GetOpt
import System.Environment (getArgs)
import System.Exit
import System.IO
import qualified UnliftIO.Exception as E

import Common
import Imports
import Server

data Options = Options
    { optDebugLog :: Bool
    , optShow :: Bool
    , optKeyLogFile :: Maybe FilePath
    , optGroups :: [Group]
    , optCertFile :: FilePath
    , optKeyFile :: FilePath
    }
    deriving (Show)

defaultOptions :: Options
defaultOptions =
    Options
        { optDebugLog = False
        , optShow = False
        , optKeyLogFile = Nothing
        , -- excluding FFDHE8192 for retry
          optGroups = [X25519, X448, P256, P521]
        , optCertFile = "servercert.pem"
        , optKeyFile = "serverkey.pem"
        }

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
    let keyLog = getLogger optKeyLogFile
        creds = Credentials [cred]
    runTCPServer (Just host) port $ \sock -> do
        let sparams = getServerParams creds optGroups smgr keyLog
        E.bracket (contextNew sock sparams) bye $ \ctx -> do
            handshake ctx
            when (optDebugLog || optShow) $ putStrLn "------------------------"
            when optDebugLog $
                getInfo ctx >>= printHandshakeInfo
            server ctx optShow

getServerParams
    :: Credentials
    -> [Group]
    -> SessionManager
    -> (String -> IO ())
    -> ServerParams
getServerParams creds groups sm keyLog =
    def
        { serverSupported = supported
        , serverShared = shared
        , serverHooks = hooks
        , serverDebug = debug
        , serverEarlyDataSize = 2048
        }
  where
    shared =
        def
            { sharedCredentials = creds
            , sharedSessionManager = sm
            }
    supported =
        def
            { supportedGroups = groups
            }
    hooks = def{onALPNClientSuggest = Just chooseALPN}
    debug = def{debugKeyLogger = keyLog}

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
