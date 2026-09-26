{-# LANGUAGE OverloadedStrings #-}

module SecretSpec where

import Crypto.Debug (debugShow)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import Data.List (isInfixOf)
import Network.TLS (Version (TLS13))
import Network.TLS.Extra.Cipher (ciphersuite_default)
import Network.TLS.Internal (SessionData (..))
import Network.TLS.QUIC
import Test.Hspec

-- | The traffic secrets reach a QUIC implementation through
-- 'quicInstallKeys', so a trace of what it is handed must not write them to a
-- log.  'debugShow' is how a debugging session asks for them on purpose.
spec :: Spec
spec = do
    describe "Show of the QUIC secret types" $ do
        it "does not print an early traffic secret" $
            check $
                EarlySecretInfo cipher clientSecret
        it "does not print the handshake traffic secrets" $
            check $
                HandshakeSecretInfo cipher (clientSecret, serverSecret)
        it "does not print the application traffic secrets" $
            check $
                ApplicationSecretInfo (clientSecret, serverSecret)
    describe "Show of a resumable session" $
        it "does not print the session secret" $ do
            let shown = show sessionData
            show (B.replicate 32 0xa5) `isInfixOf` shown `shouldBe` False
            "<secret>" `isInfixOf` shown `shouldBe` True
            show (B.replicate 32 0xa5)
                `isInfixOf` debugShow sessionData
                `shouldBe` True
  where
    sessionData =
        SessionData
            { sessionVersion = TLS13
            , sessionCipher = 0x1301
            , sessionCompression = 0
            , sessionClientSNI = Just "example.com"
            , sessionSecret = B.replicate 32 0xa5
            , sessionGroup = Nothing
            , sessionTicketInfo = Nothing
            , sessionALPN = Nothing
            , sessionMaxEarlyDataSize = 0
            , sessionFlags = []
            }
    cipher = case ciphersuite_default of
        c : _ -> c
        [] -> error "ciphersuite_default is empty"
    clientSecret = ClientTrafficSecret $ BA.convert $ B.replicate 32 0xa5
    serverSecret = ServerTrafficSecret $ BA.convert $ B.replicate 32 0x5a
    hexOf w = concat $ replicate 32 w
    check x = do
        let shown = show x
        hexOf "a5" `isInfixOf` shown `shouldBe` False
        hexOf "5a" `isInfixOf` shown `shouldBe` False
        "<secret>" `isInfixOf` shown `shouldBe` True
        hexOf "a5" `isInfixOf` debugShow x `shouldBe` True
