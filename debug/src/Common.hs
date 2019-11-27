-- Disable this warning so we can still test deprecated functionality.
{-# OPTIONS_GHC -fno-warn-warnings-deprecations #-}
module Common
    ( printCiphers
    , printDHParams
    , printGroups
    , readNumber
    , readCiphers
    , readDHParams
    , readGroups
    , printHandshakeInfo
    , makeAddrInfo
    , AddrInfo(..)
    , getCertificateStore
    ) where

import Data.Char (isDigit)
import Numeric (showHex)
import Network.Socket

import Data.X509.CertificateStore
import System.X509

import Network.TLS hiding (HostName)
import Network.TLS.Extra.Cipher
import Network.TLS.Extra.FFDHE

import Imports

namedDHParams :: [(String, DHParams)]
namedDHParams =
    [ ("ffdhe2048", ffdhe2048)
    , ("ffdhe3072", ffdhe3072)
    , ("ffdhe4096", ffdhe4096)
    , ("ffdhe6144", ffdhe6144)
    , ("ffdhe8192", ffdhe8192)
    ]

namedCiphersuites :: [(String, [CipherID])]
namedCiphersuites =
    [ ("all",       map cipherID ciphersuite_all)
    , ("default",   map cipherID ciphersuite_default)
    , ("strong",    map cipherID ciphersuite_strong)
    ]

namedGroups :: [(String, Group)]
namedGroups =
    [ ("ffdhe2048", FFDHE2048)
    , ("ffdhe3072", FFDHE3072)
    , ("ffdhe4096", FFDHE4096)
    , ("ffdhe6144", FFDHE6144)
    , ("ffdhe8192", FFDHE8192)
    , ("p256", P256)
    , ("p384", P384)
    , ("p521", P521)
    , ("x25519", X25519)
    , ("x448", X448)
    ]

readNumber :: (Num a, Read a) => String -> Maybe a
readNumber s
    | all isDigit s = Just $ read s
    | otherwise     = Nothing

readCiphers :: String -> Maybe [CipherID]
readCiphers s =
    case lookup s namedCiphersuites of
        Nothing -> (:[]) `fmap` readNumber s
        just    -> just

readDHParams :: String -> IO (Maybe DHParams)
readDHParams s =
    case lookup s namedDHParams of
        Nothing -> (Just . read) `fmap` readFile s
        mparams -> return mparams

readGroups :: String -> Maybe [Group]
readGroups s = traverse (`lookup` namedGroups) (split ',' s)

printCiphers :: IO ()
printCiphers = do
    putStrLn "Supported ciphers"
    putStrLn "====================================="
    forM_ ciphersuite_all $ \c -> do
        putStrLn (pad 50 (cipherName c) ++ " = " ++ pad 5 (show $ cipherID c) ++ "  0x" ++ showHex (cipherID c) "")
    putStrLn ""
    putStrLn "Ciphersuites"
    putStrLn "====================================="
    forM_ namedCiphersuites $ \(name, _) -> putStrLn name
  where
    pad n s
        | length s < n = s ++ replicate (n - length s) ' '
        | otherwise    = s

printDHParams :: IO ()
printDHParams = do
    putStrLn "DH Parameters"
    putStrLn "====================================="
    forM_ namedDHParams $ \(name, _) -> putStrLn name
    putStrLn "(or /path/to/dhparams)"

printGroups :: IO ()
printGroups = do
    putStrLn "Groups"
    putStrLn "====================================="
    forM_ namedGroups $ \(name, _) -> putStrLn name

printHandshakeInfo ctx = do
    info <- contextGetInformation ctx
    case info of
        Nothing -> return ()
        Just i  -> do
            putStrLn ("version: " ++ show (infoVersion i))
            putStrLn ("cipher: " ++ show (infoCipher i))
            putStrLn ("compression: " ++ show (infoCompression i))
            putStrLn ("group: " ++ maybe "(none)" show (infoNegotiatedGroup i))
            when (infoVersion i < TLS13) $
                putStrLn ("extended master secret: " ++ show (infoExtendedMasterSec i))
            when (infoVersion i == TLS13) $ do
                putStrLn ("handshake emode: " ++ show (fromJust (infoTLS13HandshakeMode i)))
                putStrLn ("early data accepted: " ++ show (infoIsEarlyDataAccepted i))
    sni <- getClientSNI ctx
    case sni of
        Nothing -> return ()
        Just n  -> putStrLn ("server name indication: " ++ n)

makeAddrInfo :: Maybe HostName -> PortNumber -> IO AddrInfo
makeAddrInfo maddr port = do
    let flgs = [AI_ADDRCONFIG, AI_NUMERICSERV, AI_PASSIVE]
        hints = defaultHints {
            addrFlags = flgs
          , addrSocketType = Stream
          }
    head <$> getAddrInfo (Just hints) maddr (Just $ show port)

split :: Char -> String -> [String]
split _ "" = []
split c s = case break (c==) s of
    ("",r)  -> split c (tail r)
    (s',"") -> [s']
    (s',r)  -> s' : split c (tail r)

getCertificateStore :: [FilePath] -> IO CertificateStore
getCertificateStore []    = getSystemCertificateStore
getCertificateStore paths = foldM readPathAppend mempty paths
  where
    readPathAppend acc path = do
        mstore <- readCertificateStore path
        case mstore of
            Nothing -> error ("invalid certificate store: " ++ path)
            Just st -> return $! mappend st acc
