{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE TypeApplications #-}

module ByeSpec where

import Control.Concurrent
import Control.Concurrent.Async
import Control.Concurrent.STM
import qualified Control.Exception as E
import Control.Monad (when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Either (isLeft)
import Data.IORef
import GHC.Clock (getMonotonicTime)
import qualified Network.Socket as N
import qualified Network.Socket.ByteString as NB
import Network.TLS
import System.Timeout
import Test.Hspec
import Test.QuickCheck (generate)

import Arbitrary
import PipeChan

spec :: Spec
spec = describe "bye" $ do
    it "waits for the last handshake messages with the backend's recvWith" $ do
        (cParams, sParams) <- generate arbitraryPairParams13
        pipe <- newPipe
        _ <- runPipe pipe
        used <- newIORef False
        let noop = return ()
            cBackend = Backend noop noop (writePipeC pipe) (readPipeC pipe)
            sBackend = Backend noop noop (writePipeS pipe) (readPipeS pipe)
        cCtx <-
            contextNew (GivingUp cBackend $ recvWithVia (readPipeC pipe) used) cParams
        sCtx <- contextNew sBackend sParams
        concurrently_ (handshake cCtx) (handshake sCtx)
        -- close_notify still goes out after the receive in 'bye'.
        timeout 5000000 (concurrently (bye cCtx) (recvData sCtx))
            `shouldReturn` Just ((), mempty)
        readIORef used `shouldReturn` True

    it "gives up on a receive over a socket" $ do
#if MIN_VERSION_network(3,2,12)
        (cs, ss) <- N.socketPair N.AF_UNIX N.Stream N.defaultProtocol
        case getBackendRecvWith cs of
            Nothing -> expectationFailure "a socket should be able to give up"
            Just (RecvWith recvWith) -> do
                late <- registerDelay 50000
                recvWith 4 (readTVar late >>= check) `shouldReturn` Left ()
                NB.sendAll ss "abcd"
                recvWith 4 (retry :: STM ()) `shouldReturn` Right "abcd"
                -- The bytes received before giving up are not lost.
                NB.sendAll ss "ab"
                late' <- registerDelay 50000
                recvWith 4 (readTVar late' >>= check) `shouldReturn` Right "ab"
        N.close cs
        N.close ss
#else
        pendingWith "needs network 3.2.12 or later"
#endif

    it "does not wait with a backend which cannot give up" $ do
        (cParams, sParams) <- generate arbitraryPairParams13
        pipe <- newPipe
        _ <- runPipe pipe
        armed <- newIORef False
        readAfter <- newIORef False
        let noop = return ()
            recvC n = do
                a <- readIORef armed
                when a $ writeIORef readAfter True
                readPipeC pipe n
            cBackend = Backend noop noop (writePipeC pipe) recvC
            sBackend = Backend noop noop (writePipeS pipe) (readPipeS pipe)
        cCtx <- contextNew cBackend cParams
        sCtx <- contextNew sBackend sParams
        concurrently_ (handshake cCtx) (handshake sCtx)
        writeIORef armed True
        timeout 5000000 (bye cCtx) `shouldReturn` Just ()
        readIORef readAfter `shouldReturn` False

    it "neither waits nor sends after a failed handshake" $ do
        (cParams, sParams) <- generate arbitraryPairParams13
        pipe <- newPipe
        _ <- runPipe pipe
        used <- newIORef False
        let noop = return ()
            cBackend = Backend noop noop (writePipeC pipe) (readPipeC pipe)
            sBackend = Backend noop noop (writePipeS pipe) (readPipeS pipe)
            reject _ = return $ CertificateUsageReject $ CertificateRejectOther "test"
            sParams' =
                sParams
                    { serverWantClientCert = True
                    , serverHooks = (serverHooks sParams){onClientCertificate = reject}
                    }
        cCtx <- contextNew cBackend cParams
        sCtx <-
            contextNew (GivingUp sBackend $ recvWithVia (readPipeS pipe) used) sParams'
        (_, r) <-
            concurrently
                (E.try @E.SomeException $ handshake cCtx)
                (E.try @TLSException $ handshake sCtx)
        r `shouldSatisfy` isLeft
        timeout 5000000 (bye sCtx) `shouldReturn` Just ()
        readIORef used `shouldReturn` False

    it "does not throw when the peer has gone" $ do
        (cParams, sParams) <- generate arbitraryPairParams13
        (cs, ss) <- N.socketPair N.AF_UNIX N.Stream N.defaultProtocol
        cCtx <- contextNew cs cParams
        sCtx <- contextNew ss sParams
        concurrently_ (handshake cCtx) (handshake sCtx)
        N.close ss
        timeout 5000000 (bye cCtx) `shouldReturn` Just ()
        N.close cs

    it "sends close_notify when the last handshake message is cut short" $ do
        (cParams, sParams) <- generate arbitraryPairParams13
        pipe <- newPipe
        _ <- runPipe pipe
        let noop = return ()
            cBackend = Backend noop noop (writePipeC pipe) (readPipeC pipe)
            sBackend = Backend noop noop (writePipeS pipe) (readPipeS pipe)
            -- Half of a record body arrives before giving up.
            cut = RecvWith $ \n giveUp -> do
                bs <- readPipeC pipe n
                if n == 5
                    then return $ Right bs
                    else atomically giveUp >> return (Right $ B.take (n `div` 2) bs)
        cCtx <- contextNew (GivingUp cBackend cut) cParams
        sCtx <- contextNew sBackend sParams
        concurrently_ (handshake cCtx) (handshake sCtx)
        timeout 5000000 (concurrently (bye cCtx) (recvData sCtx))
            `shouldReturn` Just ((), mempty)
        closeNotifyReceived sCtx `shouldReturn` True

    it "waits for the last handshake messages a few seconds at most" $ do
        (cParams, sParams) <- generate arbitraryPairParams13
        pipe <- newPipe
        _ <- runPipe pipe
        sent <- newIORef False
        let noop = return ()
            -- Every answer is late, which makes the RTT two seconds.
            sendC bs = writeIORef sent True >> writePipeC pipe bs
            recvC n = do
                s <- atomicModifyIORef' sent (\x -> (False, x))
                when s $ threadDelay 2000000
                readPipeC pipe n
            cBackend = Backend noop noop sendC recvC
            sBackend = Backend noop noop (writePipeS pipe) (readPipeS pipe)
            never = RecvWith $ \_ giveUp -> Left <$> atomically giveUp
        cCtx <- contextNew (GivingUp cBackend never) cParams
        sCtx <- contextNew sBackend sParams
        concurrently_ (handshake cCtx) (handshake sCtx)
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
        n <- readIORef sent
        timeout 5000000 (bye sCtx) `shouldReturn` Just ()
        readIORef sent `shouldReturn` n

    it "does not wait after a failed send" $ do
        (cParams, sParams) <- generate arbitraryPairParams13
        pipe <- newPipe
        _ <- runPipe pipe
        failing <- newIORef False
        used <- newIORef False
        let noop = return ()
            sendC bs = do
                f <- readIORef failing
                when f $ E.throwIO E.ThreadKilled
                writePipeC pipe bs
            cBackend = Backend noop noop sendC (readPipeC pipe)
            sBackend = Backend noop noop (writePipeS pipe) (readPipeS pipe)
        cCtx <-
            contextNew (GivingUp cBackend $ recvWithVia (readPipeC pipe) used) cParams
        sCtx <- contextNew sBackend sParams
        concurrently_ (handshake cCtx) (handshake sCtx)
        writeIORef failing True
        E.try @E.AsyncException (sendData cCtx "abc") `shouldReturn` Left E.ThreadKilled
        timeout 5000000 (bye cCtx) `shouldReturn` Just ()
        readIORef used `shouldReturn` False

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

-- | A backend which can give up on a receive.
data GivingUp = GivingUp Backend RecvWith

instance HasBackend GivingUp where
    initializeBackend _ = return ()
    getBackend (GivingUp b _) = b
    getBackendRecvWith (GivingUp _ f) = Just f

-- | A receive given up on in STM, over a pipe which cannot be: the bytes
--   read after giving up are lost, which closing the connection allows.
recvWithVia :: (Int -> IO ByteString) -> IORef Bool -> RecvWith
recvWithVia rd used = RecvWith $ \n giveUp -> do
    writeIORef used True
    v <- newEmptyTMVarIO
    _ <- forkIO $ rd n >>= atomically . putTMVar v
    atomically $ (Right <$> takeTMVar v) `orElse` (Left <$> giveUp)
