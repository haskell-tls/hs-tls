{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Data.IORef
import qualified Data.Map.Strict as M
import Data.X509.CertificateStore
import Network.Run.TCP
import Network.TLS
import Network.TLS.ECH.Config
import Network.TLS.Extra.Cipher
import Network.TLS.Extra.CipherCBC
import Network.TLS.Extra.FFDHE
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
    , optGroups :: Maybe [Group]
    , optCertFile :: FilePath
    , optKeyFile :: FilePath
    , optECHConfigFile :: Maybe FilePath
    , optECHKeyFile :: Maybe FilePath
    , optTraceKey :: Bool
    , optUseWeakCiphers :: Bool
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
        , optGroups = Nothing
        , optCertFile = "servercert.pem"
        , optKeyFile = "serverkey.pem"
        , optECHConfigFile = Nothing
        , optECHKeyFile = Nothing
        , optTraceKey = False
        , optUseWeakCiphers = False
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
        (ReqArg (\gs o -> o{optGroups = Just $ readGroups gs}) "<groups>")
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
    , Option
        []
        ["ech-config"]
        (ReqArg (\fl o -> o{optECHConfigFile = Just fl}) "<file>")
        "ECH config file"
    , Option
        []
        ["ech-key"]
        (ReqArg (\fl o -> o{optECHKeyFile = Just fl}) "<file>")
        "ECH key file"
    , Option
        []
        ["trace-key"]
        (NoArg (\o -> o{optTraceKey = True}))
        "Trace transcript hash"
    , Option
        []
        ["use-weak-ciphers"]
        (NoArg (\o -> o{optUseWeakCiphers = True}))
        "accept deprecated ciphers and relax checks (for tlsfuzzer)"
    ]

usage :: String
usage = "Usage: tls-server [OPTION] addr port"

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
    let groups = fromMaybe defaultGroups optGroups
        defaultGroups
            | optUseWeakCiphers = supportedGroups defaultSupported
            -- excluding FFDHE8192 for retry
            | otherwise = FFDHE8192 `delete` supportedGroups defaultSupported
    when (null groups) $ do
        putStrLn "Error: unsupported groups"
        exitFailure
    smgr <- newSessionManager
    Right cred@(!_cc, !_priv) <- credentialLoadX509 optCertFile optKeyFile
    mstore <- do
        mstore' <- case optTrustedAnchor of
            Nothing -> Just <$> getSystemCertificateStore
            Just file -> readCertificateStore file
        when (isNothing mstore') $ showUsageAndExit "cannot set trusted anchor"
        return mstore'
    ech <- case optECHKeyFile of
        Nothing -> case optECHConfigFile of
            Nothing -> return ([], [])
            Just _ -> showUsageAndExit "must specify ECH key file, too"
        Just ekeyf -> case optECHConfigFile of
            Nothing -> showUsageAndExit "must specify ECH config file, too"
            Just ecnff -> do
                ekey <- loadECHSecretKeys [ekeyf]
                ecnf <- loadECHConfigList ecnff
                return (ekey, ecnf)
    let keyLog = getLogger optKeyLogFile
        printError
            | optDebugLog = putStrLn
            | otherwise = \_ -> return ()
        traceKey
            | optTraceKey = putStrLn
            | otherwise = \_ -> return ()
        creds = Credentials [cred]
    makeCipherShowPretty
    runTCPServer (Just host) port $ \sock -> do
        let sparams =
                getServerParams
                    creds
                    optUseWeakCiphers
                    groups
                    smgr
                    keyLog
                    optClientAuth
                    mstore
                    ech
                    printError
                    traceKey
        ctx <- contextNew sock sparams
        when optDebugLog $
            contextHookSetLogging
                ctx
                defaultLogging
                    { loggingPacketSent = putStrLn . ("<< " ++)
                    , loggingPacketRecv = putStrLn . (">> " ++)
                    --                    , loggingIOSent = \bs -> putStrLn $ "{{ " ++ showBytesHex bs
                    --                    , loggingIORecv = \hd bs -> putStrLn $ "}} " ++ show hd ++ " " ++ showBytesHex bs
                    }
        when (optDebugLog || optShow) $ putStrLn "------------------------"
        handshake ctx
        when optDebugLog $
            getInfo ctx >>= printHandshakeInfo
        server ctx optShow
        bye ctx

getServerParams
    :: Credentials
    -> Bool
    -> [Group]
    -> SessionManager
    -> (String -> IO ())
    -> Bool
    -> Maybe CertificateStore
    -> ([(Word8, ByteString)], ECHConfigList)
    -> (String -> IO ())
    -> (String -> IO ())
    -> ServerParams
getServerParams creds weak groups sm keyLog clientAuth mstore (ekey, ecnf) printError traceKey =
    defaultParamsServer
        { serverSupported = supported
        , serverShared = shared
        , serverHooks = hooks
        , serverDebug = debug
        , serverEarlyDataSize = 2048
        , serverWantClientCert = clientAuth
        , serverECHKey = ekey
        , serverDHEParams = if weak then Just ffdhe2048 else Nothing
        }
  where
    shared =
        defaultShared
            { sharedCredentials = creds
            , sharedSessionManager = sm
            , sharedCAStore = case mstore of
                Just store -> store
                Nothing -> sharedCAStore defaultShared
            , sharedECHConfigList = ecnf
            , sharedLimit =
                defaultLimit
                    { limitRecordSize = Just 16384
                    }
            }
    supported =
        defaultSupported
            { supportedCiphers = ciphers
            , supportedGroups = groups
            , supportedExtendedMainSecret =
                if weak then AllowEMS else supportedExtendedMainSecret defaultSupported
            , supportedClientInitiatedRenegotiation =
                weak || supportedClientInitiatedRenegotiation defaultSupported
            }
    ciphers
        | weak = ciphersuite_default ++ ciphersForFuzzer
        | otherwise = ciphersuite_default
    hooks =
        defaultServerHooks
            { onALPNClientSuggest = Just chooseALPN
            , onClientCertificate = case mstore of
                Nothing -> onClientCertificate defaultServerHooks
                Just _
                    | weak -> acceptEmptyCertificate
                    | otherwise ->
                        validateClientCertificate (sharedCAStore shared) (sharedValidationCache shared)
            }
    debug =
        defaultDebugParams
            { debugKeyLogger = keyLog
            , debugError = printError
            , debugTraceKey = traceKey
            }
    acceptEmptyCertificate cc
        | isNullCertificateChain cc = return CertificateUsageAccept
        | otherwise =
            validateClientCertificate
                (sharedCAStore shared)
                (sharedValidationCache shared)
                cc

----------------------------------------------------------------
-- Deprecated ciphers, accepted only with --use-weak-ciphers.
-- tlsfuzzer uses them in its TLS 1.2 tests.

ciphersForFuzzer :: [Cipher]
ciphersForFuzzer =
    [ cipher_ECDHE_RSA_WITH_AES_128_CBC_SHA
    , cipher_DHE_RSA_WITH_AES_128_CBC_SHA
    , cipher_RSA_WITH_AES_256_CBC_SHA
    , cipher_RSA_WITH_AES_128_CBC_SHA
    , cipher_DHE_RSA_WITH_AES_128_GCM_SHA256
    , cipher_RSA_WITH_AES_128_GCM_SHA256
    , cipher_RSA_WITH_AES_256_GCM_SHA384
    , cipher_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    , cipher13_AES_128_CCM_8_SHA256
    ]
        ++ ciphersuite_pfs_sha2_cbc

-- CBC with HMAC-SHA1, derived from the SHA-2 ones in CipherCBC.
cipher_RSA_WITH_AES_128_CBC_SHA :: Cipher
cipher_RSA_WITH_AES_128_CBC_SHA =
    cipher_DHE_RSA_AES128_SHA256
        { cipherID = 0x002F
        , cipherName = "TLS_RSA_WITH_AES_128_CBC_SHA"
        , cipherHash = SHA1
        , cipherPRFHash = Nothing
        , cipherKeyExchange = CipherKeyExchange_RSA
        , cipherMinVer = Just SSL3
        }

cipher_RSA_WITH_AES_256_CBC_SHA :: Cipher
cipher_RSA_WITH_AES_256_CBC_SHA =
    cipher_DHE_RSA_AES256_SHA256
        { cipherID = 0x0035
        , cipherName = "TLS_RSA_WITH_AES_256_CBC_SHA"
        , cipherHash = SHA1
        , cipherPRFHash = Nothing
        , cipherKeyExchange = CipherKeyExchange_RSA
        , cipherMinVer = Just SSL3
        }

cipher_DHE_RSA_WITH_AES_128_CBC_SHA :: Cipher
cipher_DHE_RSA_WITH_AES_128_CBC_SHA =
    cipher_RSA_WITH_AES_128_CBC_SHA
        { cipherID = 0x0033
        , cipherName = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
        , cipherKeyExchange = CipherKeyExchange_DHE_RSA
        , cipherMinVer = Nothing
        }

cipher_ECDHE_RSA_WITH_AES_128_CBC_SHA :: Cipher
cipher_ECDHE_RSA_WITH_AES_128_CBC_SHA =
    cipher_RSA_WITH_AES_128_CBC_SHA
        { cipherID = 0xC013
        , cipherName = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
        , cipherKeyExchange = CipherKeyExchange_ECDHE_RSA
        , cipherMinVer = Just TLS10
        }

-- AES-GCM with RSA key exchange, derived from the DHE ones.
cipher_RSA_WITH_AES_128_GCM_SHA256 :: Cipher
cipher_RSA_WITH_AES_128_GCM_SHA256 =
    cipher_DHE_RSA_WITH_AES_128_GCM_SHA256
        { cipherID = 0x009C
        , cipherName = "TLS_RSA_WITH_AES_128_GCM_SHA256"
        , cipherKeyExchange = CipherKeyExchange_RSA
        }

cipher_RSA_WITH_AES_256_GCM_SHA384 :: Cipher
cipher_RSA_WITH_AES_256_GCM_SHA384 =
    cipher_DHE_RSA_WITH_AES_256_GCM_SHA384
        { cipherID = 0x009D
        , cipherName = "TLS_RSA_WITH_AES_256_GCM_SHA384"
        , cipherKeyExchange = CipherKeyExchange_RSA
        }

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
                M.lookup key <$> readIORef ref
            , sessionResumeOnlyOnce = \key -> do
                M.lookup key <$> readIORef ref
            , sessionEstablish = \key val -> do
                atomicModifyIORef' ref $ \m -> (M.insert key val m, Nothing)
            , sessionInvalidate = \key -> do
                atomicModifyIORef' ref $ \m -> (M.delete key m, ())
            , sessionUseTicket = False
            }
