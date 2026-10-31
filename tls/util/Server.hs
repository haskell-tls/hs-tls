{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Server where

import Control.Concurrent
import qualified Control.Exception as E
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

-- An HTTP request is answered with HTML, anything else is echoed.
-- tlsfuzzer's test-lengths.py sends "A..A\n", or just "\n", and expects
-- it back.
server :: Context -> Bool -> IO ()
server ctx showRequest = do
    bs <- recvData ctx
    case C8.uncons bs of
        Nothing -> return ()
        Just ('G', _) -> handleHTML ctx showRequest bs
        Just _ -> do
            sendData ctx $ CL8.fromStrict bs
            echo ctx

echo :: Context -> IO ()
echo ctx = loop
  where
    loop = do
        bs <- recvData ctx
        when (bs /= "") $ do
            sendData ctx $ CL8.fromStrict bs
            loop

-- A dedicated thread keeps calling 'recvData', which also processes the
-- response to a post-handshake authentication.
handleHTML :: Context -> Bool -> ByteString -> IO ()
handleHTML ctx showRequest ini = do
    chan <- newChan
    E.bracket (forkIO $ reader chan) killThread $ \_ -> do
        getLine <- newSource chan ini
        process getLine
  where
    reader chan = do
        r <- E.try $ recvData ctx
        case r of
            Right bs | bs /= "" -> writeChan chan bs >> reader chan
            Right _ -> writeChan chan ""
            Left (_ :: E.SomeException) -> writeChan chan ""
    process getLine = do
        bs <- getLine
        when ("GET /keyupdate" `BS.isPrefixOf` bs) $ do
            r <- updateKey ctx TwoWay
            putStrLn $ "Updating key..." ++ if r then "OK" else "NG"
        mcheck <-
            if "GET /secret" `BS.isPrefixOf` bs
                then Just <$> requestCertificateAsync ctx
                else return Nothing
        when (bs /= "") $ do
            when showRequest $ do
                BS.putStr bs
                BS.putStr "\n"
            consume getLine
            ok <- maybe (return True) authenticated mcheck
            when ok $ sendData ctx html
    -- The response is sent only after the authentication.
    authenticated check = do
        r <- check True
        putStrLn $ "Post handshake authentication..." ++ show r
        return $ case r of
            PHAFailed _ -> False
            _ -> True
    consume getLine = do
        bs <- getLine
        when (bs /= "") $ do
            when showRequest $ do
                BS.putStr bs
                BS.putStr "\n"
            consume getLine

newSource :: Chan ByteString -> ByteString -> IO (IO ByteString)
newSource chan ini = do
    ref <- newIORef ini
    return $ getline ref
  where
    getline :: IORef ByteString -> IO ByteString
    getline ref = do
        bs0 <- readIORef ref
        case BS.breakSubstring "\n" bs0 of
            (_, "") -> do
                bs1 <- readChan chan
                if bs1 == ""
                    then do
                        -- EOF stays for the next call.
                        writeChan chan ""
                        writeIORef ref ""
                        return bs0
                    else do
                        writeIORef ref (bs0 <> bs1)
                        getline ref
            (bs1, bs2) -> do
                writeIORef ref $ BS.drop 1 bs2
                return $ BS.dropWhileEnd (== 0x0d) bs1
