module HandshakeSpec where

import qualified Data.ByteString as B
import Data.IORef
import Data.List
import Data.Maybe
import Network.TLS
import Network.TLS.Extra.Cipher
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

import Arbitrary
import PipeChan
import Run

spec :: Spec
spec = do
    describe "pipe" $ do
        it "can setup a channel" pipe_work
    describe "handshake" $ do
        prop "can run TLS 1.2" handshake_simple
        prop "can run TLS 1.3" handshake13_simple
        prop "can update key for TLS 1.3" handshake_update_key
        prop "can prevent downgrade attack" handshake13_downgrade
        prop "can negotiate hash and signature" handshake_hashsignatures
        prop "can negotiate cipher suite" handshake_ciphersuites
        prop "can negotiate group" handshake_groups
        prop "can negotiate elliptic curve" handshake_ec
        prop "can fallback for certificate with cipher" handshake_cert_fallback_cipher
        prop "can fallback for certificate with hash and signature" handshake_cert_fallback_hs

--------------------------------------------------------------

pipe_work :: IO ()
pipe_work = do
    pipe <- newPipe
    _ <- runPipe pipe

    let bSize = 16
    n <- generate (choose (1, 32))

    let d1 = B.replicate (bSize * n) 40
    let d2 = B.replicate (bSize * n) 45

    d1' <- writePipeA pipe d1 >> readPipeB pipe (B.length d1)
    d1 `shouldBe` d1'

    d2' <- writePipeB pipe d2 >> readPipeA pipe (B.length d2)
    d2 `shouldBe` d2'

--------------------------------------------------------------

handshake_simple :: (ClientParams, ServerParams) -> IO ()
handshake_simple = runTLSPipeSimple

--------------------------------------------------------------

newtype CSP13 = CSP13 (ClientParams, ServerParams) deriving (Show)

instance Arbitrary CSP13 where
    arbitrary = CSP13 <$> arbitraryPairParams13

handshake13_simple :: CSP13 -> IO ()
handshake13_simple (CSP13 params) = runTLSPipeSimple13 params hs Nothing
  where
    cgrps = supportedGroups $ clientSupported $ fst params
    sgrps = supportedGroups $ serverSupported $ snd params
    hs = if head cgrps `elem` sgrps then FullHandshake else HelloRetryRequest

--------------------------------------------------------------

handshake13_downgrade :: (ClientParams, ServerParams) -> IO ()
handshake13_downgrade (cparam, sparam) = do
    versionForced <-
        generate $ elements (supportedVersions $ clientSupported cparam)
    let debug' = (serverDebug sparam){debugVersionForced = Just versionForced}
        sparam' = sparam{serverDebug = debug'}
        params = (cparam, sparam')
        downgraded =
            (isVersionEnabled TLS13 params && versionForced < TLS13)
                || (isVersionEnabled TLS12 params && versionForced < TLS12)
    if downgraded
        then runTLSInitFailure params
        else runTLSPipeSimple params

handshake_update_key :: (ClientParams, ServerParams) -> IO ()
handshake_update_key = runTLSPipeSimpleKeyUpdate

--------------------------------------------------------------

handshake_hashsignatures
    :: ([HashAndSignatureAlgorithm], [HashAndSignatureAlgorithm]) -> IO ()
handshake_hashsignatures (clientHashSigs, serverHashSigs) = do
    tls13 <- generate arbitrary
    let version = if tls13 then TLS13 else TLS12
        ciphers =
            [ cipher_ECDHE_RSA_AES256GCM_SHA384
            , cipher_ECDHE_ECDSA_AES256GCM_SHA384
            , cipher_ECDHE_RSA_AES128CBC_SHA
            , cipher_ECDHE_ECDSA_AES128CBC_SHA
            , cipher_DHE_RSA_AES128_SHA1
            , cipher_TLS13_AES128GCM_SHA256
            ]
    (clientParam, serverParam) <-
        generate $
            arbitraryPairParamsWithVersionsAndCiphers
                ([version], [version])
                (ciphers, ciphers)
    let clientParam' =
            clientParam
                { clientSupported =
                    (clientSupported clientParam)
                        { supportedHashSignatures = clientHashSigs
                        }
                }
        serverParam' =
            serverParam
                { serverSupported =
                    (serverSupported serverParam)
                        { supportedHashSignatures = serverHashSigs
                        }
                }
        commonHashSigs = clientHashSigs `intersect` serverHashSigs
        shouldFail
            | tls13 = all incompatibleWithDefaultCurve commonHashSigs
            | otherwise = null commonHashSigs
    if shouldFail
        then runTLSInitFailure (clientParam', serverParam')
        else runTLSPipeSimple (clientParam', serverParam')
  where
    incompatibleWithDefaultCurve (h, SignatureECDSA) = h /= HashSHA256
    incompatibleWithDefaultCurve _ = False

handshake_ciphersuites :: ([Cipher], [Cipher]) -> IO ()
handshake_ciphersuites (clientCiphers, serverCiphers) = do
    tls13 <- generate arbitrary
    let version = if tls13 then TLS13 else TLS12
    (clientParam, serverParam) <-
        generate $
            arbitraryPairParamsWithVersionsAndCiphers
                ([version], [version])
                (clientCiphers, serverCiphers)
    let adequate = cipherAllowedForVersion version
        shouldSucceed = any adequate (clientCiphers `intersect` serverCiphers)
    if shouldSucceed
        then runTLSPipeSimple (clientParam, serverParam)
        else runTLSInitFailure (clientParam, serverParam)

--------------------------------------------------------------

handshake_groups :: ([Group], [Group]) -> IO ()
handshake_groups (clientGroups, serverGroups) = do
    tls13 <- generate arbitrary
    let versions = if tls13 then [TLS13] else [TLS12]
        ciphers =
            [ cipher_ECDHE_RSA_AES256GCM_SHA384
            , cipher_ECDHE_RSA_AES128CBC_SHA
            , cipher_DHE_RSA_AES256GCM_SHA384
            , cipher_DHE_RSA_AES128_SHA1
            , cipher_TLS13_AES128GCM_SHA256
            ]
    (clientParam, serverParam) <-
        generate $
            arbitraryPairParamsWithVersionsAndCiphers
                (versions, versions)
                (ciphers, ciphers)
    denyCustom <- generate arbitrary
    let groupUsage =
            if denyCustom
                then GroupUsageUnsupported "custom group denied"
                else GroupUsageValid
        clientParam' =
            clientParam
                { clientSupported =
                    (clientSupported clientParam)
                        { supportedGroups = clientGroups
                        }
                , clientHooks =
                    (clientHooks clientParam)
                        { onCustomFFDHEGroup = \_ _ -> return groupUsage
                        }
                }
        serverParam' =
            serverParam
                { serverSupported =
                    (serverSupported serverParam)
                        { supportedGroups = serverGroups
                        }
                }
        isCustom = maybe True isCustomDHParams (serverDHEParams serverParam')
        mCustomGroup = serverDHEParams serverParam' >>= dhParamsGroup
        isClientCustom = maybe True (`notElem` clientGroups) mCustomGroup
        commonGroups = clientGroups `intersect` serverGroups
        shouldFail = null commonGroups && (tls13 || isClientCustom && denyCustom)
        p minfo = isNothing (minfo >>= infoSupportedGroup) == (null commonGroups && isCustom)
    if shouldFail
        then runTLSInitFailure (clientParam', serverParam')
        else runTLSPipePredicate (clientParam', serverParam') p

--------------------------------------------------------------

newtype SG = SG [Group] deriving (Show)

instance Arbitrary SG where
    arbitrary = SG <$> sublistOf sigGroups
      where
        sigGroups = [P256]

handshake_ec :: SG -> IO ()
handshake_ec (SG sigGroups) = do
    let versions = [TLS12, TLS13]
        ciphers =
            [ cipher_ECDHE_ECDSA_AES256GCM_SHA384
            , cipher_ECDHE_ECDSA_AES128CBC_SHA
            , cipher_TLS13_AES128GCM_SHA256
            ]
        ecdhGroups = [X25519, X448] -- always enabled, so no ECDHE failure
        hashSignatures =
            [ (HashSHA256, SignatureECDSA)
            ]
    clientVersion <- generate $ elements versions
    (clientParam, serverParam) <-
        generate $
            arbitraryPairParamsWithVersionsAndCiphers
                ([clientVersion], versions)
                (ciphers, ciphers)
    clientGroups <- generate $ sublistOf sigGroups
    clientHashSignatures <- generate $ sublistOf hashSignatures
    serverHashSignatures <- generate $ sublistOf hashSignatures
    credentials <- generate arbitraryCredentialsOfEachCurve
    let clientParam' =
            clientParam
                { clientSupported =
                    (clientSupported clientParam)
                        { supportedGroups = clientGroups ++ ecdhGroups
                        , supportedHashSignatures = clientHashSignatures
                        }
                }
        serverParam' =
            serverParam
                { serverSupported =
                    (serverSupported serverParam)
                        { supportedGroups = sigGroups ++ ecdhGroups
                        , supportedHashSignatures = serverHashSignatures
                        }
                , serverShared =
                    (serverShared serverParam)
                        { sharedCredentials = Credentials credentials
                        }
                }
        sigAlgs = map snd (clientHashSignatures `intersect` serverHashSignatures)
        ecdsaDenied =
            (clientVersion < TLS13 && null clientGroups)
                || (clientVersion >= TLS12 && SignatureECDSA `notElem` sigAlgs)
    if ecdsaDenied
        then runTLSInitFailure (clientParam', serverParam')
        else runTLSPipeSimple (clientParam', serverParam')

-- Tests ability to use or ignore client "signature_algorithms" extension when
-- choosing a server certificate.  Here peers allow DHE_RSA_AES128_SHA1 but
-- the server RSA certificate has a SHA-1 signature that the client does not
-- support.  Server may choose the DSA certificate only when cipher
-- DHE_DSA_AES128_SHA1 is allowed.  Otherwise it must fallback to the RSA
-- certificate.

data OC = OC [Cipher] [Cipher] deriving (Show)

instance Arbitrary OC where
    arbitrary = OC <$> sublistOf otherCiphers <*> sublistOf otherCiphers
      where
        otherCiphers =
            [ cipher_ECDHE_RSA_AES256GCM_SHA384
            , cipher_ECDHE_RSA_AES128CBC_SHA
            ]

handshake_cert_fallback_cipher :: OC -> IO ()
handshake_cert_fallback_cipher (OC clientCiphers serverCiphers)= do
    let clientVersions = [TLS12]
        serverVersions = [TLS12]
        commonCiphers = [cipher_DHE_RSA_AES128_SHA1]
        hashSignatures = [(HashSHA256, SignatureRSA), (HashSHA1, SignatureDSA)]
    chainRef <- newIORef Nothing
    (clientParam, serverParam) <-
        generate $
            arbitraryPairParamsWithVersionsAndCiphers
                (clientVersions, serverVersions)
                (clientCiphers ++ commonCiphers, serverCiphers ++ commonCiphers)
    let clientParam' =
            clientParam
                { clientSupported =
                    (clientSupported clientParam)
                        { supportedHashSignatures = hashSignatures
                        }
                , clientHooks =
                    (clientHooks clientParam)
                        { onServerCertificate = \_ _ _ chain ->
                            writeIORef chainRef (Just chain) >> return []
                        }
                }
    runTLSPipeSimple (clientParam', serverParam)
    serverChain <- readIORef chainRef
    isLeafRSA serverChain `shouldBe` True

-- Same as above but testing with supportedHashSignatures directly instead of
-- ciphers, and thus allowing TLS13.  Peers accept RSA with SHA-256 but the
-- server RSA certificate has a SHA-1 signature.  When Ed25519 is allowed by
-- both client and server, the Ed25519 certificate is selected.  Otherwise the
-- server fallbacks to RSA.
--
-- Note: SHA-1 is supposed to be disallowed in X.509 signatures with TLS13
-- unless client advertises explicit support.  Currently this is not enforced by
-- the library, which is useful to test this scenario.  SHA-1 could be replaced
-- by another algorithm.

data OHS = OHS [HashAndSignatureAlgorithm] [HashAndSignatureAlgorithm] deriving (Show)

instance Arbitrary OHS where
    arbitrary = OHS <$> sublistOf otherHS <*> sublistOf otherHS
      where
        otherHS = [(HashIntrinsic, SignatureEd25519)]

handshake_cert_fallback_hs :: OHS -> IO ()
handshake_cert_fallback_hs (OHS clientHS serverHS)= do
    tls13 <- generate arbitrary
    let versions = if tls13 then [TLS13] else [TLS12]
        ciphers =
            [ cipher_ECDHE_RSA_AES128GCM_SHA256
            , cipher_ECDHE_ECDSA_AES128GCM_SHA256
            , cipher_TLS13_AES128GCM_SHA256
            ]
        commonHS =
            [ (HashSHA256, SignatureRSA)
            , (HashIntrinsic, SignatureRSApssRSAeSHA256)
            ]
    chainRef <- newIORef Nothing
    (clientParam, serverParam) <-
        generate $
            arbitraryPairParamsWithVersionsAndCiphers
                (versions, versions)
                (ciphers, ciphers)
    let clientParam' =
            clientParam
                { clientSupported =
                    (clientSupported clientParam)
                        { supportedHashSignatures = commonHS ++ clientHS
                        }
                , clientHooks =
                    (clientHooks clientParam)
                        { onServerCertificate = \_ _ _ chain ->
                            writeIORef chainRef (Just chain) >> return []
                        }
                }
        serverParam' =
            serverParam
                { serverSupported =
                    (serverSupported serverParam)
                        { supportedHashSignatures = commonHS ++ serverHS
                        }
                }
        eddsaDisallowed =
            (HashIntrinsic, SignatureEd25519) `notElem` clientHS
                || (HashIntrinsic, SignatureEd25519) `notElem` serverHS
    runTLSPipeSimple (clientParam', serverParam')
    serverChain <- readIORef chainRef
    isLeafRSA serverChain `shouldBe` eddsaDisallowed
