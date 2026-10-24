{-# LANGUAGE OverloadedStrings #-}

module ChannelBindingSpec where

import Control.Concurrent.Async (concurrently)
import Crypto.Error (CryptoFailable (..))
import qualified Crypto.Hash as H
import qualified Crypto.KDF.HKDF as HKDF
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import Crypto.Random (seedFromInteger)
import Data.ByteArray (convert)
import Data.ByteArray.Encoding (Base (Base16), convertFromBase)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import Data.IORef
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
        it "derives what RFC 8446 says, under SHA-256" $
            exporterFollowsRFC H.SHA256 cipher13_AES_128_GCM_SHA256
        it "derives what RFC 8446 says, under SHA-384" $
            exporterFollowsRFC H.SHA384 cipher13_AES_256_GCM_SHA384

    describe "tls-server-end-point" $ do
        it "hashes only a SHA-1-signed leaf with SHA-256 for TLS 1.2" $ do
            let credential@(chain, _) = rsaCredential (SignatureALG X509.HashSHA1 PubKeyALG_RSA)
                params =
                    tls12Params
                        cipher_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                        [ RSA_PKCS1_SHA256
                        , RSA_PKCS1_SHA1
                        ]
                        credential
            bindings <- runBindings params
            endpointValues bindings `shouldBe` both (Just (leafDigest DigestSHA256 chain))
        it "maps an MD5 certificate signature to SHA-256" $ do
            let credential@(chain, _) = rsaCredential (SignatureALG X509.HashMD5 PubKeyALG_RSA)
                params =
                    tls12Params
                        cipher_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                        [ RSA_PKCS1_SHA256
                        , RSA_PKCS1_MD5
                        ]
                        credential
            bindings <- runBindings params
            endpointValues bindings `shouldBe` both (Just (leafDigest DigestSHA256 chain))
        it "uses a SHA-384 certificate signature instead of the cipher hash" $ do
            let credential@(chain, _) = rsaCredential (SignatureALG X509.HashSHA384 PubKeyALG_RSA)
                params =
                    tls12Params
                        cipher_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                        [ RSA_PKCS1_SHA384
                        , RSA_PKCS1_SHA256
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

-- | Run a TLS 1.3 handshake, take the exporter main secret out of the key
-- log, and work out the binding from RFC 8446 here, with no help from the
-- code under test.
--
-- A fixture of the library's own output cannot do this job: break the
-- derivation, regenerate the fixture, and the test passes again.  What is
-- written out below is the specification -- HKDF-Expand-Label and
-- Derive-Secret as RFC 8446 section 7.1 defines them, assembled as section
-- 7.5 and RFC 9266 section 2 say -- so the two have to agree for a reason.
exporterFollowsRFC :: H.HashAlgorithm a => a -> Cipher -> Expectation
exporterFollowsRFC alg cipher = do
    logged <- newIORef []
    let params = withKeyLogger (\line -> modifyIORef' logged (line :)) $
            tls13Params cipher ed25519Credential
    bindings <- runBindings params
    secret <- exporterSecretOf <$> readIORef logged
    let expected = tlsExporter alg secret
    byteLists (exporterValues bindings)
        `shouldBe` byteLists (Just expected, Just expected)

-- | RFC 9266 section 2: @TLS-Exporter("EXPORTER-Channel-Binding", "", 32)@,
-- which RFC 8446 section 7.5 expands to
-- @HKDF-Expand-Label(Derive-Secret(Secret, label, ""), "exporter",
-- Hash(context_value), key_length)@.  Both the @""@ that Derive-Secret is
-- given and the empty context value reach HKDF-Expand-Label as @Hash("")@,
-- which is the step that was wrong.
tlsExporter :: H.HashAlgorithm a => a -> B.ByteString -> B.ByteString
tlsExporter alg secret =
    expandLabel alg inner "exporter" (emptyHash alg) 32
  where
    inner = deriveSecret alg secret "EXPORTER-Channel-Binding"

-- | RFC 8446 section 7.1, for the empty transcript:
-- @Derive-Secret(Secret, Label, "") =
-- HKDF-Expand-Label(Secret, Label, Transcript-Hash(""), Hash.length)@.
deriveSecret
    :: H.HashAlgorithm a => a -> B.ByteString -> B.ByteString -> B.ByteString
deriveSecret alg secret label =
    expandLabel alg secret label (emptyHash alg) (H.hashDigestSize alg)

-- | RFC 8446 section 7.1, written out: the HkdfLabel structure is a 16-bit
-- length, then @"tls13 " ++ Label@ and then the context, each with a
-- one-octet length of its own.
expandLabel
    :: H.HashAlgorithm a
    => a -> B.ByteString -> B.ByteString -> B.ByteString -> Int -> B.ByteString
expandLabel alg secret label context len = HKDF.expand (prk alg) hkdfLabel len
  where
    prk :: H.HashAlgorithm h => h -> HKDF.PRK h
    prk _ = HKDF.extractSkip secret
    hkdfLabel =
        B.concat
            [ B.pack [fromIntegral (len `div` 256), fromIntegral (len `mod` 256)]
            , opaque ("tls13 " <> label)
            , opaque context
            ]
    opaque bs = B.cons (fromIntegral (B.length bs)) bs

emptyHash :: H.HashAlgorithm a => a -> B.ByteString
emptyHash alg = convert (H.hashWith alg B.empty)

-- | The exporter main secret, as the NSS key log format writes it:
-- @EXPORTER_SECRET \<client random\> \<secret\>@, in hexadecimal.
exporterSecretOf :: [String] -> B.ByteString
exporterSecretOf ls = case [w | l <- ls, "EXPORTER_SECRET" : _ : w : _ <- [words l]] of
    hexed : _ -> case convertFromBase Base16 (C8.pack hexed) of
        Right bs -> bs
        Left err -> error ("exporterSecretOf: " ++ err)
    [] -> error "exporterSecretOf: the key log has no EXPORTER_SECRET line"

withKeyLogger
    :: (String -> IO ())
    -> (ClientParams, ServerParams)
    -> (ClientParams, ServerParams)
withKeyLogger logger (cparams, sparams) =
    ( cparams
    , sparams{serverDebug = (serverDebug sparams){debugKeyLogger = logger}}
    )

endpointValues :: Bindings -> (Maybe B.ByteString, Maybe B.ByteString)
endpointValues bindings =
    (snd (clientBindings bindings), snd (serverBindings bindings))

both :: a -> (a, a)
both value = (value, value)

tls12Params
    :: Cipher
    -> [SignatureScheme]
    -> Credential
    -> (ClientParams, ServerParams)
tls12Params cipher hashSignatures =
    bindingParams TLS12 cipher hashSignatures

tls13Params :: Cipher -> Credential -> (ClientParams, ServerParams)
tls13Params cipher =
    bindingParams
        TLS13
        cipher
        [ ED448
        , ED25519
        , RSA_PSS_RSAE_SHA256
        , RSA_PKCS1_SHA256
        ]

bindingParams
    :: Version
    -> Cipher
    -> [SignatureScheme]
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
            , -- the fixed RSA key of the expected values is 1024 bits
              supportedMinRSAKeySize = 1024
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
