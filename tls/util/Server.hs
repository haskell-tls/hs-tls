{-# LANGUAGE OverloadedStrings #-}

module Server (
    GiveUp,
    idleTimeout,
    server,
) where

import Control.Concurrent
import qualified Control.Concurrent.STM as STM
import qualified Control.Exception as E
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy.Char8 as CL8
import Data.Either (isRight)
import Data.IORef
import Network.TLS
import Prelude hiding (getLine)

import Common (tryExpected)
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

-- | Making a give-up which fires once the server is told to stop or
-- the seconds given have passed.
type GiveUp = Int -> IO (STM.STM ())

-- Seconds a client may stay silent.
idleTimeout :: Int
idleTimeout = 30

-- An HTTP request is answered with HTML, anything else is echoed.
-- tlsfuzzer's test-lengths.py sends "A..A\n", or just "\n", and expects
-- it back.
server :: Context -> GiveUp -> Bool -> IO ()
server ctx giveUp showRequest = do
    mbs <- recv ctx giveUp
    case C8.uncons <$> mbs of
        Just (Just ('G', _)) -> handleHTML ctx giveUp showRequest $ fromJust mbs
        Just (Just _) -> do
            ok <- send ctx giveUp $ fromJust mbs
            when ok $ echo ctx giveUp
        _ -> return ()

echo :: Context -> GiveUp -> IO ()
echo ctx giveUp = loop
  where
    loop = do
        mbs <- recv ctx giveUp
        forM_ mbs $ \bs -> when (bs /= "") $ do
            ok <- send ctx giveUp bs
            when ok loop

-- | 'Nothing' when giving up.
recv :: Context -> GiveUp -> IO (Maybe ByteString)
recv ctx giveUp = do
    g <- giveUp idleTimeout
    either (const Nothing) Just <$> recvDataWith ctx g

-- | 'False' when giving up or when the client has closed gracefully.
send :: Context -> GiveUp -> ByteString -> IO Bool
send ctx giveUp bs = do
    g <- giveUp idleTimeout
    isRight
        <$> respectingGracefulClose ctx (Left ()) (sendDataWith ctx (CL8.fromStrict bs) g)

-- A dedicated thread keeps calling 'recvDataWith', which also processes
-- the response to a post-handshake authentication.  It gives up once
-- the request is answered.
handleHTML :: Context -> GiveUp -> Bool -> ByteString -> IO ()
handleHTML ctx giveUp showRequest ini = do
    chan <- newChan
    done <- STM.newTVarIO False
    finished <- newEmptyMVar
    -- EOF also when the reader dies of something unexpected
    _ <-
        forkIO $
            reader chan (STM.readTVar done >>= STM.check)
                `E.finally` (writeChan chan "" >> putMVar finished ())
    getLine <- newSource chan ini
    process getLine
        `E.finally` (STM.atomically (STM.writeTVar done True) >> takeMVar finished)
  where
    reader chan stop = do
        g <- giveUp idleTimeout
        r <- tryExpected $ recvDataWith ctx (stop `STM.orElse` g)
        case r of
            Right (Right bs) | bs /= "" -> writeChan chan bs >> reader chan stop
            Left err -> putStrLn err >> writeChan chan ""
            _ -> writeChan chan ""
    process getLine = do
        bs <- getLine
        when ("GET /keyupdate" `BS.isPrefixOf` bs) $ do
            -- giving up if the peer does not read for 5 seconds
            g <- giveUp 5
            r <- updateKeyWith ctx TwoWay g
            putStrLn $
                "Updating key..."
                    ++ either (const "gave up") (\ok -> if ok then "OK" else "NG") r
        mcheck <-
            if "GET /secret" `BS.isPrefixOf` bs
                then Just <$> requestCertificateAsyncWith ctx
                else return Nothing
        when (bs /= "") $ do
            when showRequest $ do
                BS.putStr bs
                BS.putStr "\n"
            consume getLine
            ok <- maybe (return True) authenticated mcheck
            when ok $ void $ send ctx giveUp $ CL8.toStrict html
    -- The response is sent only after the authentication.
    -- giving up if the client does not respond in 10 seconds
    authenticated wait = do
        g <- giveUp 10
        r <- wait g
        putStrLn $ "Post handshake authentication..." ++ either (const "gave up") show r
        return $ case r of
            Right (PHAFailed _) -> False
            Left () -> False
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
