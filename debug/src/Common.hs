module Common
    ( printCiphers
    , printDHParams
    , readNumber
    , readCiphers
    , readDHParams
    ) where

import Control.Monad

import Data.Char (isDigit)

import Numeric (showHex)

import Network.TLS
import Network.TLS.Extra.Cipher
import Network.TLS.Extra.FFDHE

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
    , ("medium",    map cipherID ciphersuite_medium)
    , ("strong",    map cipherID ciphersuite_strong)
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
