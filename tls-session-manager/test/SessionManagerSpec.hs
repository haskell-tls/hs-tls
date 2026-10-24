{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module SessionManagerSpec where

import Control.Concurrent (threadDelay)
import Data.IORef
import Data.Maybe (isJust, isNothing)
import qualified Data.OrdPSQ as Q
import Network.TLS
import Network.TLS.Internal (Second, SessionData (..), TLS13TicketInfo (..))
import Network.TLS.SessionManager
import Network.TLS.SessionManager.Internal (
    Availability (..),
    DB (..),
    Item (..),
    clean,
    cons,
    toValue,
 )
import Test.Hspec

spec :: Spec
spec = do
    describe "newSessionManager" $ do
        it "keeps a TLS 1.3 session no longer than its ticket lifetime" $ do
            mgr <- newSessionManager defaultConfig
            _ <- sessionEstablish mgr "short" $ sessionData (Just 1)
            _ <- sessionEstablish mgr "none" $ sessionData Nothing
            threadDelay 2000000
            sessionResume mgr "short" >>= (`shouldSatisfy` isNothing)
            sessionResume mgr "none" >>= (`shouldSatisfy` isJust)
        it "does not resume an expired session before it is pruned" $ do
            mgr <- newSessionManager defaultConfig{ticketLifetime = 1}
            _ <- sessionEstablish mgr "expired" $ sessionData Nothing
            threadDelay 2000000
            sessionResume mgr "expired" >>= (`shouldSatisfy` isNothing)
        it "keeps the other session when a key is added again at the limit" $ do
            mgr <- newSessionManager defaultConfig{dbMaxSize = 2}
            -- "a" comes first both by expiry and by key, so it would be the
            -- one dropped for room
            _ <- sessionEstablish mgr "a" $ sessionData (Just 1800)
            _ <- sessionEstablish mgr "b" $ sessionData (Just 3600)
            _ <- sessionEstablish mgr "b" $ sessionData (Just 3600)
            sessionResume mgr "a" >>= (`shouldSatisfy` isJust)
        it "does not resume an invalidated session" $ do
            mgr <- newSessionManager defaultConfig
            _ <- sessionEstablish mgr "a" $ sessionData Nothing
            sessionInvalidate mgr "a"
            sessionResume mgr "a" >>= (`shouldSatisfy` isNothing)
        it "resumes a session only once for 0-RTT" $ do
            mgr <- newSessionManager defaultConfig
            _ <- sessionEstablish mgr "a" $ sessionData Nothing
            sessionResumeOnlyOnce mgr "a" >>= (`shouldSatisfy` isJust)
            sessionResumeOnlyOnce mgr "a" >>= (`shouldSatisfy` isNothing)
    -- While the reaper prunes, the sessions are taken away and an empty
    -- workload is left in their place; the pruned ones are merged back.
    describe "pruning" $ do
        it "keeps a deletion made while pruning" $ do
            v <- value
            merge <- clean 2 $ foldr (cons 2) (DB Q.empty []) [Add "a" far v, Add "b" far v]
            let DB q _ = merge $ cons 2 (Del "a") (DB Q.empty [])
            Q.member "a" q `shouldBe` False
            Q.member "b" q `shouldBe` True
        it "keeps the size limit when merging" $ do
            v <- value
            merge <- clean 2 $ foldr (cons 2) (DB Q.empty []) [Add "a" far v, Add "b" far v]
            let DB q _ = merge $ cons 2 (Add "c" far v) (DB Q.empty [])
            Q.size q `shouldBe` 2
  where
    far = maxBound `div` 2
    value = do
        ref <- newIORef Fresh
        return (toValue (sessionData Nothing), ref)

-- | Session data with a TLS 1.3 ticket of the given lifetime, if any.
sessionData :: Maybe Second -> SessionData
sessionData life =
    withoutClientCertificate $
        SessionData
            TLS13 -- version
            0x1301 -- cipher
            0 -- compression
            Nothing -- SNI
            "secret"
            Nothing -- group
            (ticketInfo <$> life)
            Nothing -- ALPN
            0 -- max early data size
            [] -- flags
  where
    ticketInfo l =
        TLS13TicketInfo{lifetime = l, ageAdd = 0, txrxTime = 0, estimatedRTT = Nothing}

-- tls 2.5 added the client certificate to SessionData.
#if MIN_VERSION_tls(2,5,0)
withoutClientCertificate :: (Maybe a -> SessionData) -> SessionData
withoutClientCertificate f = f Nothing
#else
withoutClientCertificate :: SessionData -> SessionData
withoutClientCertificate = id
#endif
