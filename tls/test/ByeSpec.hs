module ByeSpec where

import Control.Concurrent
import Control.Concurrent.Async
import Control.Concurrent.STM
import Data.ByteString (ByteString)
import Data.IORef
import Network.TLS
import System.Timeout
import Test.Hspec
import Test.QuickCheck (generate)

import Arbitrary
import PipeChan

spec :: Spec
spec = describe "bye" $
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
