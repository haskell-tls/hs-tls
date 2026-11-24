{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module ByeSpec where

import Control.Concurrent
import Control.Concurrent.Async
import qualified Control.Exception as E
import Control.Monad (forever, when)
import Data.Either (isLeft)
import Data.IORef
import GHC.Clock (getMonotonicTime)
import Network.TLS
import System.Timeout
import Test.Hspec
import Test.QuickCheck (generate)

import Arbitrary
import PipeChan

spec :: Spec
spec = describe "bye" $ do
    it "waits for the last handshake messages a few seconds at most" $ do
        (cParams, sParams) <- generate arbitraryPairParams13
        pipe <- newPipe
        _ <- runPipe pipe
        sent <- newIORef False
        armed <- newIORef False
        let noop = return ()
            -- Every answer is late, which makes the RTT two seconds.
            sendC bs = writeIORef sent True >> writePipeC pipe bs
            recvC n = do
                a <- readIORef armed
                when a $ forever $ threadDelay 1000000
                s <- atomicModifyIORef' sent (\x -> (False, x))
                when s $ threadDelay 2000000
                readPipeC pipe n
            cBackend = Backend noop noop sendC recvC
            sBackend = Backend noop noop (writePipeS pipe) (readPipeS pipe)
        cCtx <- contextNew cBackend cParams
        sCtx <- contextNew sBackend sParams
        concurrently_ (handshake cCtx) (handshake sCtx)
        writeIORef armed True
        t0 <- getMonotonicTime
        bye cCtx
        t1 <- getMonotonicTime
        (t1 - t0) `shouldSatisfy` (< 4)

    it "sends nothing after a failed send" $ do
        (cParams, sParams) <- generate arbitraryPairParams13
        pipe <- newPipe
        _ <- runPipe pipe
        failing <- newIORef False
        sent <- newIORef (0 :: Int)
        let noop = return ()
            sendS bs = do
                f <- readIORef failing
                when f $ E.throwIO E.ThreadKilled
                modifyIORef' sent (+ 1)
                writePipeS pipe bs
            cBackend = Backend noop noop (writePipeC pipe) (readPipeC pipe)
            sBackend = Backend noop noop sendS (readPipeS pipe)
        cCtx <- contextNew cBackend cParams
        sCtx <- contextNew sBackend sParams
        concurrently_ (handshake cCtx) (handshake sCtx)
        writeIORef failing True
        E.try @E.AsyncException (sendData sCtx "abc") `shouldReturn` Left E.ThreadKilled
        writeIORef failing False
        -- An asynchronous exception is not thrown again.
        E.try @TLSException (sendData sCtx "abc")
            `shouldReturn` Left (PostHandshake (Error_Misc "a previous send failed"))
        n <- readIORef sent
        timeout 5000000 (bye sCtx) `shouldReturn` Just ()
        readIORef sent `shouldReturn` n

    it "throws the exception of the failed send again" $ do
        (cParams, sParams) <- generate arbitraryPairParams13
        pipe <- newPipe
        _ <- runPipe pipe
        failing <- newIORef False
        let noop = return ()
            sendS bs = do
                f <- atomicModifyIORef' failing (\x -> (False, x))
                when f $ E.throwIO $ E.ErrorCall "broken"
                writePipeS pipe bs
            cBackend = Backend noop noop (writePipeC pipe) (readPipeC pipe)
            sBackend = Backend noop noop sendS (readPipeS pipe)
        cCtx <- contextNew cBackend cParams
        sCtx <- contextNew sBackend sParams
        concurrently_ (handshake cCtx) (handshake sCtx)
        writeIORef failing True
        E.try (sendData sCtx "abc") `shouldReturn` Left (E.ErrorCall "broken")
        E.try (sendData sCtx "abc") `shouldReturn` Left (E.ErrorCall "broken")

    it "does not wait after a failed send" $ do
        (cParams, sParams) <- generate arbitraryPairParams13
        pipe <- newPipe
        _ <- runPipe pipe
        failing <- newIORef False
        readAfter <- newIORef False
        let noop = return ()
            sendC bs = do
                f <- readIORef failing
                when f $ E.throwIO E.ThreadKilled
                writePipeC pipe bs
            recvC n = do
                f <- readIORef failing
                when f $ writeIORef readAfter True
                readPipeC pipe n
            cBackend = Backend noop noop sendC recvC
            sBackend = Backend noop noop (writePipeS pipe) (readPipeS pipe)
        cCtx <- contextNew cBackend cParams
        sCtx <- contextNew sBackend sParams
        concurrently_ (handshake cCtx) (handshake sCtx)
        writeIORef failing True
        E.try @E.AsyncException (sendData cCtx "abc") `shouldReturn` Left E.ThreadKilled
        timeout 5000000 (bye cCtx) `shouldReturn` Just ()
        readIORef readAfter `shouldReturn` False

    it "sends nothing after a handshake whose send failed" $ do
        (cParams, sParams) <- generate arbitraryPairParams13
        pipe <- newPipe
        _ <- runPipe pipe
        let noop = return ()
            broken _ = E.throwIO $ E.ErrorCall "broken"
            cBackend = Backend noop noop (writePipeC pipe) (readPipeC pipe)
            sBackend = Backend noop noop broken (readPipeS pipe)
        cCtx <- contextNew cBackend cParams
        sCtx <- contextNew sBackend sParams
        withAsync (handshake cCtx) $ \_ -> do
            r <- E.try @TLSException $ handshake sCtx
            r `shouldSatisfy` isLeft
            timeout 5000000 (bye sCtx) `shouldReturn` Just ()

    it "ends the connection when the answer to close_notify fails" $ do
        (cParams, sParams) <- generate arbitraryPairParams13
        pipe <- newPipe
        _ <- runPipe pipe
        failing <- newIORef False
        let noop = return ()
            sendS bs = do
                f <- readIORef failing
                when f $ E.throwIO E.ThreadKilled
                writePipeS pipe bs
            cBackend = Backend noop noop (writePipeC pipe) (readPipeC pipe)
            sBackend = Backend noop noop sendS (readPipeS pipe)
        cCtx <- contextNew cBackend cParams
        sCtx <- contextNew sBackend sParams
        concurrently_ (handshake cCtx) (handshake sCtx)
        writeIORef failing True
        withAsync (bye cCtx) $ \_ -> do
            E.try @E.AsyncException (recvData sCtx) `shouldReturn` Left E.ThreadKilled
            timeout 1000000 (E.try @TLSException (recvData sCtx))
                `shouldReturn` Just (Left (PostHandshake Error_EOF))
