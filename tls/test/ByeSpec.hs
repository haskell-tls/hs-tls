{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE CPP #-}

module ByeSpec where

import Control.Concurrent
import Control.Concurrent.Async
import Control.Concurrent.STM
import Control.Monad (when)
import Data.ByteString (ByteString)
import Data.IORef
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
