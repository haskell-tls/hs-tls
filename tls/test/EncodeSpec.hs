module EncodeSpec where

import Codec.Compression.Zlib (compress)
import Control.Exception (bracket_, evaluate)
import Control.Monad (forM_, void)
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
    describe "extension decoding" $ do
        prop "yields Nothing rather than throwing, for any message type" $
            \ws -> forM_ extensionDecoders $ \(name, decode) ->
                forM_ [minBound .. maxBound] $ \mt ->
                    decode mt (B.pack ws) `shouldReturn` name
    describe "handshake record length" $ do
        -- A handshake message carries a 24-bit length, and the fragments are
        -- held until the message is whole.  Refusing at the header means
        -- refusing to hold anything: the length arrives in the first four
        -- octets, before any of the body.
        it "refuses a length past the limit, on its header alone" $ do
            let tooBig = maxHandshakeSize + 1
            isGotError (decodeHandshakeRecord (handshakeHeader tooBig)) `shouldBe` True
            isGotError (decodeHandshakeRecord13 (handshakeHeader tooBig)) `shouldBe` True
        it "refuses the largest a 24-bit length can say" $ do
            let header = handshakeHeader 0xffffff
            isGotError (decodeHandshakeRecord header) `shouldBe` True
            isGotError (decodeHandshakeRecord13 header) `shouldBe` True
        -- Still waiting for the body rather than refusing it: at the limit
        -- the header alone is not enough to decide anything is wrong.
        it "asks for more at the limit itself" $ do
            let header = handshakeHeader maxHandshakeSize
            isGotPartial (decodeHandshakeRecord header) `shouldBe` True
            isGotPartial (decodeHandshakeRecord13 header) `shouldBe` True
        it "still decodes a message of an ordinary size" $ do
            let body = B.replicate 1000 0
                record = handshakeHeader (B.length body) `B.append` body
            gotThisMuch (B.length body) (decodeHandshakeRecord record) `shouldBe` True
            gotThisMuch (B.length body) (decodeHandshakeRecord13 record) `shouldBe` True

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

-- | A handshake record header: a type octet then a 24-bit length.
handshakeHeader :: Int -> ByteString
handshakeHeader len =
    B.pack
        [ 1 -- ClientHello
        , fromIntegral (len `div` 65536)
        , fromIntegral ((len `div` 256) `mod` 256)
        , fromIntegral (len `mod` 256)
        ]

isGotError :: GetResult a -> Bool
isGotError (GotError _) = True
isGotError _ = False

isGotPartial :: GetResult a -> Bool
isGotPartial (GotPartial _) = True
isGotPartial _ = False

gotThisMuch :: Int -> GetResult (a, ByteString) -> Bool
gotThisMuch n (GotSuccess (_, content)) = B.length content == n
gotThisMuch _ _ = False

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

-- | Every 'Extension' instance, each wrapped so that the decoded value is
-- forced inside IO.  A partial 'extensionDecode' therefore surfaces as a
-- thrown exception the test can see, rather than as a thunk nobody looks at.
--
-- The name is threaded through as the return value only so that a failure
-- report says which instance it was.
type Decoder a = MessageType -> ByteString -> Maybe a

extensionDecoders :: [(String, MessageType -> ByteString -> IO String)]
extensionDecoders =
    [
      entry "ServerName" (extensionDecode :: Decoder ServerName),
      entry "MaxFragmentLength" (extensionDecode :: Decoder MaxFragmentLength),
      entry "SecureRenegotiation" (extensionDecode :: Decoder SecureRenegotiation),
      entry "ApplicationLayerProtocolNegotiation" (extensionDecode :: Decoder ApplicationLayerProtocolNegotiation),
      entry "ExtendedMainSecret" (extensionDecode :: Decoder ExtendedMainSecret),
      entry "CompressCertificate" (extensionDecode :: Decoder CompressCertificate),
      entry "SupportedGroups" (extensionDecode :: Decoder SupportedGroups),
      entry "EcPointFormatsSupported" (extensionDecode :: Decoder EcPointFormatsSupported),
      entry "RecordSizeLimit" (extensionDecode :: Decoder RecordSizeLimit),
      entry "SessionTicket" (extensionDecode :: Decoder SessionTicket),
      entry "HeartBeat" (extensionDecode :: Decoder HeartBeat),
      entry "SignatureAlgorithms" (extensionDecode :: Decoder SignatureAlgorithms),
      entry "SignatureAlgorithmsCert" (extensionDecode :: Decoder SignatureAlgorithmsCert),
      entry "SupportedVersions" (extensionDecode :: Decoder SupportedVersions),
      entry "KeyShare" (extensionDecode :: Decoder KeyShare),
      entry "PostHandshakeAuth" (extensionDecode :: Decoder PostHandshakeAuth),
      entry "PskKeyExchangeModes" (extensionDecode :: Decoder PskKeyExchangeModes),
      entry "PreSharedKey" (extensionDecode :: Decoder PreSharedKey),
      entry "EarlyDataIndication" (extensionDecode :: Decoder EarlyDataIndication),
      entry "Cookie" (extensionDecode :: Decoder Cookie),
      entry "CertificateAuthorities" (extensionDecode :: Decoder CertificateAuthorities),
      entry "EchOuterExtensions" (extensionDecode :: Decoder EchOuterExtensions),
      entry "EncryptedClientHello" (extensionDecode :: Decoder EncryptedClientHello)
    ]
  where
    entry name decode = (name, \mt bs -> name <$ evaluate (length (show (decode mt bs))))

