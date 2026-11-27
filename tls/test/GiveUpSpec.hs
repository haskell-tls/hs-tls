{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module GiveUpSpec where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async
import Control.Concurrent.STM
import qualified Control.Exception as E
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Either (isLeft)
import GHC.Clock (getMonotonicTime)
import qualified Network.Socket as N
import qualified Network.Socket.ByteString as NB
import Network.TLS
import System.Timeout
import Test.Hspec
import Test.QuickCheck (generate, suchThat)

import Arbitrary

spec :: Spec
spec = describe "giving up" $ do
#if MIN_VERSION_network(3,2,12)
    it "handshakeWith gives up on a silent server" $
        withSockets $ \(cs, _ss) -> do
            (cParams, _) <- generate arbitraryPairParams13
            cCtx <- contextNew cs cParams
            timeout 5000000 (handshakeWith cCtx =<< lateBy 50000)
                `shouldReturn` Just (Left ())

    it "handshakeWith and recvDataWith work as usual" $
        withPair $ \(cCtx, _) (sCtx, _) -> do
            sendData cCtx "abc"
            timeout 5000000 (recvDataWith sCtx (retry :: STM ())) `shouldReturn` Just (Right "abc")

    it "recvDataWith gives up between records, leaving the context usable" $
        withPair $ \(cCtx, _) (sCtx, _) -> do
            timeout 5000000 (recvDataWith sCtx =<< lateBy 50000) `shouldReturn` Just (Left ())
            sendData cCtx "abc"
            timeout 5000000 (recvData sCtx) `shouldReturn` Just "abc"

    it "recvDataWith gives up inside a record, breaking the context" $
        withPair $ \(_, cs) (sCtx, _) -> do
            -- the first byte of a record, and no more
            NB.sendAll cs "\x17"
            r <- timeout 5000000 $ E.try @TLSException (recvDataWith sCtx =<< lateBy 50000)
            r `shouldBe` Just (Right (Left ()))
            r' <- timeout 5000000 $ E.try @TLSException (recvData sCtx)
            fmap isLeft r' `shouldBe` Just True

#if !defined(mingw32_HOST_OS)
    -- On Windows, 'timeout' does not interrupt a receive on a socket.
    it "recvDataWith gives up inside a record with a give-up which fires once" $
        withPair $ \(_, cs) (sCtx, _) -> do
            let drain = timeout 200000 (NB.recv cs 4096) >>= mapM_ (const drain)
            drain -- the session tickets
            -- a header of 100 bytes, and 10 of them
            NB.sendAll cs $ "\x17\x03\x03\x00\x64" <> B.replicate 10 0
            var <- newEmptyTMVarIO
            withAsync (threadDelay 50000 >> atomically (putTMVar var ())) $ \_ -> do
                r <- timeout 5000000 $ E.try @TLSException (recvDataWith sCtx (takeTMVar var))
                r `shouldBe` Just (Right (Left ()))
            -- not taken as a short record, which is answered with an alert
            timeout 200000 (NB.recv cs 100) `shouldReturn` Nothing
#endif

    it "recvDataWith gives up waiting for another reader" $
        withPair $ \(cCtx, _) (sCtx, _) ->
            withAsync (recvData sCtx) $ \reader -> do
                waitReading
                timeout 5000000 (recvDataWith sCtx =<< lateBy 50000) `shouldReturn` Just (Left ())
                sendData cCtx "abc"
                timeout 5000000 (wait reader) `shouldReturn` Just "abc"

    it "sendDataWith gives up at once without sending" $
        withPair $ \(cCtx, _) (sCtx, _) -> do
            timeout 5000000 (sendDataWith sCtx "abc" (return ())) `shouldReturn` Just (Left ())
            timeout 5000000 (sendData sCtx "def") `shouldReturn` Just ()
            timeout 5000000 (recvData cCtx) `shouldReturn` Just "def"

#if !defined(mingw32_HOST_OS)
    it "sendDataWith gives up on a peer which does not read" $
        withPair $ \_ (sCtx, _) -> do
            timeout 5000000 (sendDataWith sCtx big =<< lateBy 100000)
                `shouldReturn` Just (Left ())
            r <- timeout 5000000 $ E.try @TLSException $ sendData sCtx "abc"
            fmap isLeft r `shouldBe` Just True

    it "sendDataWith gives up waiting for another writer" $
        withPair $ \_ (sCtx, _) ->
            withAsync (sendData sCtx big) $ \_ -> do
                waitReading
                timeout 5000000 (sendDataWith sCtx "abc" =<< lateBy 50000)
                    `shouldReturn` Just (Left ())

    it "recvDataWith gives up on the KeyUpdate it owes, waiting for another writer" $
        withPair $ \(cCtx, _) (sCtx, _) ->
            withAsync (sendData sCtx big) $ \_ -> do
                waitReading
                _ <- updateKey cCtx TwoWay
                r <- timeout 5000000 $ E.try @TLSException (recvDataWith sCtx =<< lateBy 100000)
                r `shouldBe` Just (Right (Left ()))
                -- the KeyUpdate is not answered, so the context is broken
                r' <- timeout 5000000 $ E.try @TLSException $ recvData sCtx
                fmap isLeft r' `shouldBe` Just True

    it "byeWith gives up sooner than bye" $
        withPair $ \_ (sCtx, _) ->
            withAsync (sendData sCtx big) $ \_ -> do
                waitReading
                t0 <- getMonotonicTime
                timeout 5000000 (byeWith sCtx =<< lateBy 50000) `shouldReturn` Just ()
                t1 <- getMonotonicTime
                (t1 - t0) `shouldSatisfy` (< 0.5)

    it "handshake reports a rejected client certificate, then works as usual" $ do
        withClientAuth False $ \cCtx sCtx -> do
            let try' = E.try @TLSException . handshake
            r <- timeout 5000000 $ concurrently (try' cCtx) (try' sCtx)
            fmap (\(c, s) -> (isLeft c, isLeft s)) r `shouldBe` Just (True, True)
        withClientAuth True $ \cCtx sCtx -> do
            timeout 5000000 (concurrently_ (handshake cCtx) (handshake sCtx)) `shouldReturn` Just ()
            sendData cCtx "hello"
            timeout 5000000 (recvData sCtx) `shouldReturn` Just "hello"
#endif
#else
    it "needs network 3.2.12 or later" $ pendingWith "network < 3.2.12"
#endif
  where
    big = L.fromStrict $ B.replicate 16000000 0
    -- letting the other thread start
    waitReading = timeout 100000 (atomically retry :: IO ()) >> return ()

-- | An 'STM' action which succeeds after the microseconds.
lateBy :: Int -> IO (STM ())
lateBy us = do
    late <- registerDelay us
    return $ readTVar late >>= check

withSockets :: ((N.Socket, N.Socket) -> IO a) -> IO a
withSockets =
    E.bracket
        (N.socketPair N.AF_UNIX N.Stream N.defaultProtocol)
        (\(cs, ss) -> N.close cs >> N.close ss)

-- | TLS 1.3 over a socket pair, the client sending a certificate which the
-- server accepts or rejects.
withClientAuth :: Bool -> (Context -> Context -> IO a) -> IO a
withClientAuth accept body = withSockets $ \(cs, ss) -> do
    (cParams, sParams) <- generate arbitraryPairParams13
    cred <- generate $ arbitraryClientCredential TLS13 `suchThat` (not . isCredentialDSA)
    let cParams' =
            cParams
                { clientHooks =
                    (clientHooks cParams){onCertificateRequest = \_ -> return $ Just cred}
                }
        sParams' =
            sParams
                { serverWantClientCert = True
                , serverHooks =
                    (serverHooks sParams){onClientCertificate = \_ -> return usage}
                }
        usage
            | accept = CertificateUsageAccept
            | otherwise = CertificateUsageReject CertificateRejectUnknownCA
    cCtx <- contextNew cs cParams'
    sCtx <- contextNew ss sParams'
    body cCtx sCtx

-- | TLS 1.3 over a socket pair, the handshake done with 'handshakeWith'.
withPair :: ((Context, N.Socket) -> (Context, N.Socket) -> IO a) -> IO a
withPair body = withSockets $ \(cs, ss) -> do
    (cParams, sParams) <- generate arbitraryPairParams13
    cCtx <- contextNew cs cParams
    sCtx <- contextNew ss sParams
    r <-
        timeout 5000000 $
            concurrently
                (handshakeWith cCtx (retry :: STM ()))
                (handshakeWith sCtx (retry :: STM ()))
    r `shouldBe` Just (Right (), Right ())
    body (cCtx, cs) (sCtx, ss)
