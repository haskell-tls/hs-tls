{-# LANGUAGE CPP #-}
-- Disable this warning so we can still test deprecated functionality.
{-# OPTIONS_GHC -fno-warn-warnings-deprecations #-}

module Common (
    printDHParams,
    printGroups,
    readNumber,
    readDHParams,
    readGroups,
    getCertificateStore,
    getLogger,
    namedGroups,
    getInfo,
    printHandshakeInfo,
) where

import Data.Char (isDigit)
import Data.X509.CertificateStore
import Network.TLS hiding (HostName)
import Network.TLS.Extra.FFDHE
import System.Exit
import System.X509

import Imports

namedDHParams :: [(String, DHParams)]
namedDHParams =
    [ ("ffdhe2048", ffdhe2048)
    , ("ffdhe3072", ffdhe3072)
    , ("ffdhe4096", ffdhe4096)
    , ("ffdhe6144", ffdhe6144)
    , ("ffdhe8192", ffdhe8192)
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
    | otherwise = Nothing

readDHParams :: String -> IO (Maybe DHParams)
readDHParams s =
    case lookup s namedDHParams of
        Nothing -> (Just . read) `fmap` readFile s
        mparams -> return mparams

readGroups :: String -> [Group]
readGroups s = case traverse (`lookup` namedGroups) (split ',' s) of
    Nothing -> []
    Just gs -> gs

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

split :: Char -> String -> [String]
split _ "" = []
split c s = case break (c ==) s of
    ("", _ : rs) -> split c rs
    (s', "") -> [s']
    (s', _ : rs) -> s' : split c rs

getCertificateStore :: [FilePath] -> IO CertificateStore
getCertificateStore [] = getSystemCertificateStore
getCertificateStore paths = foldM readPathAppend mempty paths
  where
    readPathAppend acc path = do
        mstore <- readCertificateStore path
        case mstore of
            Nothing -> error ("invalid certificate store: " ++ path)
            Just st -> return $! mappend st acc

getLogger :: Maybe FilePath -> (String -> IO ())
getLogger Nothing = \_ -> return ()
getLogger (Just file) = \msg -> appendFile file (msg ++ "\n")

getInfo :: Context -> IO Information
getInfo ctx = do
    minfo <- contextGetInformation ctx
    case minfo of
        Nothing -> do
            putStrLn "Erro: information cannot be obtained"
            exitFailure
        Just info -> return info

printHandshakeInfo :: Information -> IO ()
printHandshakeInfo i = do
    putStrLn $ "Version: " ++ show (infoVersion i)
    putStrLn $ "Cipher: " ++ show (infoCipher i)
    putStrLn $ "Compression: " ++ show (infoCompression i)
    putStrLn $ "Groups: " ++ maybe "(none)" show (infoSupportedGroup i)
    when (infoVersion i < TLS13) $ do
        putStrLn $ "Extended master secret: " ++ show (infoExtendedMainSecret i)
        putStrLn $ "Resumption: " ++ show (infoTLS12Resumption i)
    when (infoVersion i == TLS13) $ do
        putStrLn $ "Handshake mode: " ++ show (fromJust (infoTLS13HandshakeMode i))
        putStrLn $ "Early data accepted: " ++ show (infoIsEarlyDataAccepted i)
        putStrLn $ "Encrypted client hello accepted: " ++ show (infoIsECHAccepted i)
