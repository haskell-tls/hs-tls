{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Client (
    Aux (..),
    Cli,
    clientHTTP11,
    clientDNS,
) where

import qualified Data.ByteString.Base16 as BS16
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy.Char8 as CL8
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NE
import Network.Socket
import Network.TLS

import Imports

data Aux = Aux
    { auxAuthority :: HostName
    , auxPort :: ServiceName
    , auxDebugPrint :: String -> IO ()
    , auxShow :: ByteString -> IO ()
    , auxReadResumptionData :: IO [(SessionID, SessionData)]
    }

type Cli = Aux -> NonEmpty ByteString -> Context -> IO ()

clientHTTP11 :: Cli
clientHTTP11 aux@Aux{..} paths ctx = do
    sendData ctx $
        CL8.fromStrict $
            "GET "
                <> NE.head paths
                <> " HTTP/1.1\r\n"
                <> "Host: "
                <> C8.pack auxAuthority
                <> "\r\n"
                <> "Connection: close\r\n"
                <> "\r\n"
    consume ctx aux

clientDNS :: Cli
clientDNS Aux{..} _paths ctx = do
    sendData
        ctx
        "\x00\x2c\xdc\xe3\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x03\x77\x77\x77\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"
    bs <- recvData ctx
    auxShow $ "Reply: " <> BS16.encode bs
    auxShow "\n"

consume :: Context -> Aux -> IO ()
consume ctx Aux{..} = loop
  where
    loop = do
        bs <- recvData ctx
        if bs == ""
            then auxShow "\n"
            else auxShow bs >> loop
