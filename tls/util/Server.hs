{-# LANGUAGE OverloadedStrings #-}

module Server where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy.Char8 as BL8
import Data.IORef
import Network.TLS
import Prelude hiding (getLine)

import Imports

server :: Context -> Bool -> IO ()
server ctx showRequest = do
    recvRequest ctx showRequest
    sendData ctx $
        -- "<>" creates *chunks* of lazy ByteString, resulting
        -- many TLS fragments.
        -- To prevent this, strict ByteString is created first and
        -- converted into lazy one.
        BL8.fromStrict $
            "HTTP/1.1 200 OK\r\n"
                <> "Context-Type: text/html\r\n"
                <> "Content-Length: "
                <> C8.pack (show (BS.length body))
                <> "\r\n"
                <> "\r\n"
                <> body
  where
    body = "<html><<body>Hello world!</body></html>"

recvRequest :: Context -> Bool -> IO ()
recvRequest ctx showRequest = do
    getLine <- newSource ctx
    loop getLine
  where
    loop getLine = do
        bs <- getLine
        when (bs /= "") $ do
            when showRequest $ do
                BS.putStr bs
                BS.putStr "\n"
            loop getLine

newSource :: Context -> IO (IO ByteString)
newSource ctx = do
    ref <- newIORef ""
    return $ getline ref
  where
    getline :: IORef ByteString -> IO ByteString
    getline ref = do
        bs0 <- readIORef ref
        case BS.breakSubstring "\n" bs0 of
            (_, "") -> do
                bs1 <- recvData ctx
                writeIORef ref (bs0 <> bs1)
                getline ref
            (bs1, bs2) -> do
                writeIORef ref $ BS.drop 1 bs2
                return $ BS.dropWhileEnd (== 0x0d) bs1
