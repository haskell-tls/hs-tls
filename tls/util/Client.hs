{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Client (
    Aux (..),
    Cli,
    clientHTTP11,
    clientDNS,
    orExit,
) where

import Control.Concurrent.STM (STM)
import qualified Data.ByteString.Base16 as BS16
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy.Char8 as CL8
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NE
import Network.Socket
import Network.TLS
import System.Exit

import Imports

data Aux = Aux
    { auxAuthority :: HostName
    , auxPort :: ServiceName
    , auxDebugPrint :: String -> IO ()
    , auxShow :: ByteString -> IO ()
    , auxReadResumptionData :: IO [(SessionID, SessionData)]
    , auxGiveUp :: STM ()
    -- ^ The deadline of the connection
    }

type Cli = Aux -> NonEmpty ByteString -> Context -> IO ()

clientHTTP11 :: Cli
clientHTTP11 aux@Aux{..} paths ctx = do
    orExit =<< sendDataWith ctx req auxGiveUp
    consume ctx aux
  where
    req =
        CL8.fromStrict $
            "GET "
                <> NE.head paths
                <> " HTTP/1.1\r\n"
                <> "Host: "
                <> C8.pack auxAuthority
                <> "\r\n"
                <> "Connection: close\r\n"
                <> "\r\n"

clientDNS :: Cli
clientDNS Aux{..} _paths ctx = do
    orExit
        =<< sendDataWith
            ctx
            "\x00\x2c\xdc\xe3\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x03\x77\x77\x77\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"
            auxGiveUp
    bs <- orExit =<< recvDataWith ctx auxGiveUp
    auxShow $ "Reply: " <> BS16.encode bs
    auxShow "\n"

consume :: Context -> Aux -> IO ()
consume ctx Aux{..} = loop
  where
    loop = do
        bs <- orExit =<< recvDataWith ctx auxGiveUp
        if bs == ""
            then auxShow "\n"
            else auxShow bs >> loop

-- | The result of a function taking a give-up, exiting with a failure
-- when the deadline has passed.
orExit :: Either () a -> IO a
orExit (Right a) = return a
orExit (Left ()) = do
    putStrLn "Error: timeout"
    exitFailure
