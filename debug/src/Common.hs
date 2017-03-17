module Common
    ( printDHParams
    , readNumber
    , readDHParams
    ) where

import Control.Monad

import Data.Char (isDigit)

import Numeric (showHex)

import Network.TLS
import Network.TLS.Extra.FFDHE

namedDHParams :: [(String, DHParams)]
namedDHParams =
    [ ("ffdhe2048", ffdhe2048)
    , ("ffdhe3072", ffdhe3072)
    , ("ffdhe4096", ffdhe4096)
    , ("ffdhe6144", ffdhe6144)
    , ("ffdhe8192", ffdhe8192)
    ]

readNumber :: (Num a, Read a) => String -> Maybe a
readNumber s
    | all isDigit s = Just $ read s
    | otherwise     = Nothing

readDHParams :: String -> IO (Maybe DHParams)
readDHParams s =
    case lookup s namedDHParams of
        Nothing -> (Just . read) `fmap` readFile s
        mparams -> return mparams

printDHParams :: IO ()
printDHParams = do
    putStrLn "DH Parameters"
    putStrLn "====================================="
    forM_ namedDHParams $ \(name, _) -> putStrLn name
    putStrLn "(or /path/to/dhparams)"
