module EncodeSpec where

import Data.ByteString (ByteString)
import Network.TLS
import Network.TLS.Internal
import Test.Hspec
import Test.QuickCheck

import Arbitrary ()

spec :: Spec
spec = do
    describe "encoder/decoder" $ do
        it "can encode/decode Header" $ property $ \x -> do
            decodeHeader (encodeHeader x) `shouldBe` Right x
        it "can encode/decode Handshake" $ property $ \x -> do
            decodeHs (encodeHandshake x) `shouldBe` Right x
        it "can encode/decode Handshake13" $ property $ \x -> do
            decodeHs13 (encodeHandshake13 x) `shouldBe` Right x

decodeHs :: ByteString -> Either TLSError Handshake
decodeHs b = verifyResult (decodeHandshake cp) $ decodeHandshakeRecord b
  where
    cp =
        CurrentParams
            { cParamsVersion = TLS12
            , cParamsKeyXchgType = Just CipherKeyExchange_RSA
            }

decodeHs13 :: ByteString -> Either TLSError Handshake13
decodeHs13 b = verifyResult decodeHandshake13 $ decodeHandshakeRecord13 b

verifyResult :: (f -> r -> a) -> GetResult (f, r) -> a
verifyResult fn result =
    case result of
        GotPartial _ -> error "got partial"
        GotError e -> error ("got error: " ++ show e)
        GotSuccessRemaining _ _ -> error "got remaining byte left"
        GotSuccess (ty, content) -> fn ty content
