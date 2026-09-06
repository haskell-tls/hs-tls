module EncodeSpec where

import Codec.Compression.Zlib (compress)
import Control.Exception (bracket_, evaluate)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import Data.Either (isLeft)
import Data.Int (Int64)
import GHC.Conc (disableAllocationLimit, enableAllocationLimit, setAllocationCounter)
import Network.TLS
import Network.TLS.Internal
import Test.Hspec
import Test.Hspec.QuickCheck

import Arbitrary ()

spec :: Spec
spec = do
    describe "encoder/decoder" $ do
        prop "can encode/decode Header" $ \x -> do
            decodeHeader (encodeHeader x) `shouldBe` Right x
        prop "can encode/decode Handshake" $ \x -> do
            decodeHs (encodeHandshake x) `shouldBe` Right x
        prop "can encode/decode Handshake13" $ \x -> do
            decodeHs13 (encodeHandshake13 x) `shouldBe` Right x
        it "round trips a valid TLS 1.3 compressed certificate" $ do
            let certificate =
                    CompressedCertificate13
                        B.empty
                        (CertificateChain_ $ CertificateChain [])
                        []
            decodeHs13 (encodeHandshake13 certificate) `shouldBe` Right certificate
        it "rejects decompressed output shorter than its declared size" $ do
            let plain = encodeCertificate13 B.empty (CertificateChain []) []
                compressed = BL.toStrict $ compress $ BL.fromStrict plain
                encoded = runPut $ do
                    putWord16 1
                    putWord24 (B.length plain + 1)
                    putOpaque24 compressed
            decodeHandshake13 HandshakeType_CompressedCertificate encoded
                `shouldSatisfy` isLeft
        it "bounds TLS 1.3 certificate decompression by the declared size" $ do
            let compressed = BL.toStrict $ compress $ BL.replicate (32 * 1024 * 1024) 0
                encoded = runPut $ do
                    putWord16 1
                    putWord24 1
                    putOpaque24 compressed
            _ <- evaluate $ B.length encoded
            decoded <-
                withinAllocationLimit (8 * 1024 * 1024) $
                    evaluate $
                        decodeHandshake13 HandshakeType_CompressedCertificate encoded
            decoded `shouldSatisfy` isLeft

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

withinAllocationLimit :: Int64 -> IO a -> IO a
withinAllocationLimit limit =
    bracket_
        (setAllocationCounter limit >> enableAllocationLimit)
        disableAllocationLimit
