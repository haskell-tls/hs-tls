{-# LANGUAGE OverloadedStrings #-}

module Server where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy.Char8 as CL8
import Data.IORef
import Network.TLS
import Prelude hiding (getLine)

import Imports

-- "<>" creates *chunks* of lazy ByteString, resulting
-- many TLS fragments.
-- To prevent this, strict ByteString is created first and
-- converted into lazy one.
html :: CL8.ByteString
html =
    CL8.fromStrict $
        "HTTP/1.1 200 OK\r\n"
            <> "Context-Type: text/html\r\n"
            <> "Content-Length: "
            <> C8.pack (show (BS.length body))
            <> "\r\n"
            <> "\r\n"
            <> body
  where
    body = "<html><<body>Hello world!</body></html>"

server :: Context -> Bool -> IO ()
server ctx showRequest = do
    bs <- recvData ctx
    case C8.uncons bs of
        Nothing -> return ()
        Just ('A', _) -> do
            sendData ctx $ CL8.fromStrict bs
            echo ctx
        Just _ -> handleHTML ctx showRequest bs

echo :: Context -> IO ()
echo ctx = loop
  where
    loop = do
        bs <- recvData ctx
        when (bs /= "") $ do
            sendData ctx $ CL8.fromStrict bs
            loop

handleHTML :: Context -> Bool -> ByteString -> IO ()
handleHTML ctx showRequest ini = do
    getLine <- newSource ctx ini
    process getLine
  where
    process getLine = do
        bs <- getLine
        when ("GET /keyupdate" `BS.isPrefixOf` bs) $ do
            r <- updateKey ctx TwoWay
            putStrLn $ "Updating key..." ++ if r then "OK" else "NG"
        when (bs /= "") $ do
            when showRequest $ do
                BS.putStr bs
                BS.putStr "\n"
            consume getLine
            sendData ctx html
    consume getLine = do
        bs <- getLine
        when (bs /= "") $ do
            when showRequest $ do
                BS.putStr bs
                BS.putStr "\n"
            consume getLine

newSource :: Context -> ByteString -> IO (IO ByteString)
newSource ctx ini = do
    ref <- newIORef ini
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
