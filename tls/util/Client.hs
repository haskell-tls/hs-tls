{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Client (
    Aux (..),
    Cli,
    client,
) where

import qualified Data.ByteString.Lazy.Char8 as CL8
import Network.Socket
import Network.TLS

import Imports

data Aux = Aux
    { auxAuthority :: HostName
    , auxPort :: ServiceName
    , auxDebug :: String -> IO ()
    , auxShow :: ByteString -> IO ()
    , auxReadResumptionData :: IO [(SessionID, SessionData)]
    }

type Cli = Aux -> [ByteString] -> Context -> IO ()

client :: Cli
client Aux{..} paths ctx = do
    sendData ctx $
        "GET "
            <> CL8.fromStrict (head paths)
            <> " HTTP/1.1\r\n"
            <> "Host: "
            <> CL8.pack auxAuthority
            <> "\r\n"
            <> "Connection: close\r\n"
            <> "\r\n"
    loop
    auxShow "\n"
  where
    loop = do
        bs <- recvData ctx
        when (bs /= "") $ do
            auxShow bs
            loop
