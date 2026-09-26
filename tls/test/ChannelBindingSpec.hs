{-# LANGUAGE OverloadedStrings #-}

module ChannelBindingSpec where

import Control.Concurrent.Async (concurrently)
import Crypto.Error (CryptoFailable (..))
import qualified Crypto.Hash as H
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import Crypto.Random (seedFromInteger)
import Data.ByteArray (convert)
import qualified Data.ByteString as B
import Data.Word (Word8)
import Data.X509 hiding (HashMD5, HashSHA1, HashSHA256, HashSHA384)
import qualified Data.X509 as X509
import Network.TLS
import Network.TLS.Extra.Cipher
import Test.Hspec

import Certificate
import PubKey
import Run

spec :: Spec
spec = do
    describe "tls-exporter" $ do
        it "matches the deterministic SHA-256 exporter fixture" $ do
            bindings <- runBindings $ tls13Params cipher13_AES_128_GCM_SHA256 ed25519Credential
            byteLists (exporterValues bindings)
                `shouldBe` byteLists (Just exporter256, Just exporter256)
        it "matches the deterministic SHA-384 exporter fixture" $ do
            bindings <- runBindings $ tls13Params cipher13_AES_256_GCM_SHA384 ed25519Credential
            byteLists (exporterValues bindings)
                `shouldBe` byteLists (Just exporter384, Just exporter384)

    describe "tls-server-end-point" $ do
        it "hashes only a SHA-1-signed leaf with SHA-256 for TLS 1.2" $ do
            let credential@(chain, _) = rsaCredential (SignatureALG X509.HashSHA1 PubKeyALG_RSA)
                params =
                    tls12Params
                        cipher_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                        [ (HashSHA256, SignatureRSA)
                        , (HashSHA1, SignatureRSA)
                        ]
                        credential
            bindings <- runBindings params
            endpointValues bindings `shouldBe` both (Just (leafDigest DigestSHA256 chain))
        it "maps an MD5 certificate signature to SHA-256" $ do
            let credential@(chain, _) = rsaCredential (SignatureALG X509.HashMD5 PubKeyALG_RSA)
                params =
                    tls12Params
                        cipher_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                        [ (HashSHA256, SignatureRSA)
                        , (HashMD5, SignatureRSA)
                        ]
                        credential
            bindings <- runBindings params
            endpointValues bindings `shouldBe` both (Just (leafDigest DigestSHA256 chain))
        it "uses a SHA-384 certificate signature instead of the cipher hash" $ do
            let credential@(chain, _) = rsaCredential (SignatureALG X509.HashSHA384 PubKeyALG_RSA)
                params =
                    tls12Params
                        cipher_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                        [ (HashSHA384, SignatureRSA)
                        , (HashSHA256, SignatureRSA)
                        ]
                        credential
            bindings <- runBindings params
            endpointValues bindings `shouldBe` both (Just (leafDigest DigestSHA384 chain))
        it "uses the same leaf-certificate definition for TLS 1.3" $ do
            let credential@(chain, _) = rsaCredential (SignatureALG X509.HashSHA256 PubKeyALG_RSA)
                params = tls13Params cipher13_AES_256_GCM_SHA384 credential
            bindings <- runBindings params
            endpointValues bindings `shouldBe` both (Just (leafDigest DigestSHA256 chain))
        it "is undefined for Ed25519 certificates" $ do
            bindings <- runBindings $ tls13Params cipher13_AES_128_GCM_SHA256 ed25519Credential
            endpointValues bindings `shouldBe` both Nothing
        it "is undefined for Ed448 certificates" $ do
            bindings <- runBindings $ tls13Params cipher13_AES_128_GCM_SHA256 ed448Credential
            endpointValues bindings `shouldBe` both Nothing

data Bindings = Bindings
    { clientBindings :: (Maybe B.ByteString, Maybe B.ByteString)
    , serverBindings :: (Maybe B.ByteString, Maybe B.ByteString)
    }

runBindings :: (ClientParams, ServerParams) -> IO Bindings
runBindings params =
    withPairContextWith (id, id) params $ \(clientContext, serverContext) -> do
        (clientResult, serverResult) <-
            concurrently (getBindings clientContext) (getBindings serverContext)
        return $ Bindings clientResult serverResult
  where
    getBindings ctx = do
        handshake ctx
        (,) <$> getTLSExporter ctx <*> getTLSServerEndPoint ctx

exporterValues :: Bindings -> (Maybe B.ByteString, Maybe B.ByteString)
exporterValues bindings =
    (fst (clientBindings bindings), fst (serverBindings bindings))

byteLists :: (Maybe B.ByteString, Maybe B.ByteString) -> (Maybe [Word8], Maybe [Word8])
byteLists (clientValue, serverValue) =
    (B.unpack <$> clientValue, B.unpack <$> serverValue)

printExporterFixtures :: IO ()
printExporterFixtures =
    mapM_ printFixture
        [ ("exporter256", cipher13_AES_128_GCM_SHA256)
        , ("exporter384", cipher13_AES_256_GCM_SHA384)
        ]
  where
    printFixture (name, cipher) = do
        bindings <- runBindings $ tls13Params cipher ed25519Credential
        case fst (exporterValues bindings) of
            Just value -> putStrLn $ name ++ " = B.pack " ++ show (B.unpack value)
            Nothing -> error $ name ++ ": exporter unavailable"

endpointValues :: Bindings -> (Maybe B.ByteString, Maybe B.ByteString)
endpointValues bindings =
    (snd (clientBindings bindings), snd (serverBindings bindings))

both :: a -> (a, a)
both value = (value, value)

tls12Params
    :: Cipher
    -> [HashAndSignatureAlgorithm]
    -> Credential
    -> (ClientParams, ServerParams)
tls12Params cipher hashSignatures =
    bindingParams TLS12 cipher hashSignatures

tls13Params :: Cipher -> Credential -> (ClientParams, ServerParams)
tls13Params cipher =
    bindingParams
        TLS13
        cipher
        [ (HashIntrinsic, SignatureEd448)
        , (HashIntrinsic, SignatureEd25519)
        , (HashIntrinsic, SignatureRSApssRSAeSHA256)
        , (HashSHA256, SignatureRSA)
        ]

bindingParams
    :: Version
    -> Cipher
    -> [HashAndSignatureAlgorithm]
    -> Credential
    -> (ClientParams, ServerParams)
bindingParams version cipher hashSignatures credential =
    (clientParams, serverParams)
  where
    supported =
        defaultSupported
            { supportedVersions = [version]
            , supportedCiphers = [cipher]
            , supportedGroups = [X25519]
            , supportedGroupsTLS13 = [[X25519]]
            , supportedHashSignatures = hashSignatures
            }
    clientParams =
        (defaultParamsClient "" B.empty)
            { clientSupported = supported
            , clientHooks =
                defaultClientHooks
                    { onServerCertificate = \_ _ _ _ -> return []
                    }
            , clientDebug = fixedDebug 1
            }
    serverParams =
        defaultParamsServer
            { serverSupported = supported
            , serverShared =
                defaultShared
                    { sharedCredentials = Credentials [credential]
                    }
            , serverDebug = fixedDebug 2
            }

fixedDebug :: Integer -> DebugParams
fixedDebug seed = defaultDebugParams{debugSeed = Just (seedFromInteger seed)}

rsaCredential :: SignatureALG -> Credential
rsaCredential signatureAlgorithm =
    (CertificateChain [leaf, intermediate], PrivKeyRSA privateKey)
  where
    (publicKey, privateKey) = rsaParams
    publicKey' = PubKeyRSA publicKey
    certificate =
        (simpleCertificate publicKey')
            { certSignatureAlg = signatureAlgorithm
            }
    (leaf, ()) =
        objectToSignedExact
            (\_ -> (B.replicate 128 1, signatureAlgorithm, ()))
            certificate
    intermediate = simpleX509 publicKey'

ed25519Credential :: Credential
ed25519Credential =
    ( CertificateChain [simpleX509 (PubKeyEd25519 publicKey)]
    , PrivKeyEd25519 privateKey
    )
  where
    privateKey = passed $ Ed25519.secretKey (B.pack [0 .. 31])
    publicKey = Ed25519.toPublic privateKey

ed448Credential :: Credential
ed448Credential =
    ( CertificateChain [simpleX509 (PubKeyEd448 publicKey)]
    , PrivKeyEd448 privateKey
    )
  where
    privateKey = passed $ Ed448.secretKey (B.pack [0 .. 56])
    publicKey = Ed448.toPublic privateKey

passed :: CryptoFailable a -> a
passed (CryptoPassed value) = value
passed (CryptoFailed err) = error (show err)

data DigestAlgorithm = DigestSHA256 | DigestSHA384

leafDigest :: DigestAlgorithm -> CertificateChain -> B.ByteString
leafDigest algorithm (CertificateChain (leaf : _)) =
    case algorithm of
        DigestSHA256 -> convert (H.hash (encodeSignedObject leaf) :: H.Digest H.SHA256)
        DigestSHA384 -> convert (H.hash (encodeSignedObject leaf) :: H.Digest H.SHA384)
leafDigest _ (CertificateChain []) = error "leafDigest: empty certificate chain"

-- These fixture-specific expected values are not published RFC test vectors.
-- Both are 32-byte bindings; 256/384 identifies the cipher suite's hash, not
-- the output size. They come from deterministic hs-tls handshakes using
-- tls13Params with AES-128-GCM-SHA256 / AES-256-GCM-SHA384, X25519,
-- ed25519Credential, and client/server RNG seeds 1/2 respectively.
--
-- Regenerate the byte strings with:
--
--   cabal repl tls:test:spec \
--     --repl-options='-e ChannelBindingSpec.printExporterFixtures'
--
-- Separate live handshakes confirm that the corrected derivation matches
-- OpenSSL for both cipher suite hashes.
exporter256, exporter384 :: B.ByteString
exporter256 =
    B.pack
        [ 18
        , 194
        , 173
        , 12
        , 29
        , 236
        , 223
        , 35
        , 48
        , 254
        , 244
        , 73
        , 135
        , 187
        , 232
        , 26
        , 198
        , 146
        , 169
        , 128
        , 211
        , 169
        , 53
        , 73
        , 121
        , 118
        , 239
        , 143
        , 21
        , 85
        , 153
        , 66
        ]
exporter384 =
    B.pack
        [ 185
        , 67
        , 147
        , 111
        , 18
        , 64
        , 200
        , 156
        , 17
        , 88
        , 210
        , 80
        , 54
        , 147
        , 183
        , 65
        , 7
        , 69
        , 57
        , 155
        , 48
        , 74
        , 172
        , 126
        , 78
        , 243
        , 122
        , 172
        , 223
        , 170
        , 239
        , 94
        ]
