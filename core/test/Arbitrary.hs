{-# LANGUAGE FlexibleInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Arbitrary where

import Control.Monad
import qualified Data.ByteString as B
import Data.Default.Class
import Data.List
import Data.Word
import Data.X509 (
    CertificateChain (..),
    ExtKeyUsageFlag,
    certPubKey,
    getCertificate,
 )
import Network.TLS
import Network.TLS.Extra.Cipher
import Network.TLS.Extra.FFDHE
import Network.TLS.Internal
import Test.QuickCheck

import Certificate
import PubKey

----------------------------------------------------------------

instance Arbitrary Version where
    arbitrary = elements [TLS12, TLS13]

instance Arbitrary ProtocolType where
    arbitrary =
        elements
            [ ProtocolType_ChangeCipherSpec
            , ProtocolType_Alert
            , ProtocolType_Handshake
            , ProtocolType_AppData
            ]

instance Arbitrary Header where
    arbitrary = Header <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary ClientRandom where
    arbitrary = ClientRandom <$> genByteString 32

instance Arbitrary ServerRandom where
    arbitrary = ServerRandom <$> genByteString 32

instance Arbitrary Session where
    arbitrary = do
        i <- choose (1, 2) :: Gen Int
        case i of
            2 -> Session . Just <$> genByteString 32
            _ -> return $ Session Nothing

instance {-# OVERLAPS #-} Arbitrary [HashAndSignatureAlgorithm] where
    arbitrary = shuffle supportedSignatureSchemes

instance Arbitrary DigitallySigned where
    arbitrary = DigitallySigned <$> (head <$> arbitrary) <*> genByteString 32

instance Arbitrary ExtensionRaw where
    arbitrary =
        let arbitraryContent = choose (0, 40) >>= genByteString
         in ExtensionRaw <$> (ExtensionID <$> arbitrary) <*> arbitraryContent

instance Arbitrary CertificateType where
    arbitrary =
        elements
            [ CertificateType_RSA_Sign
            , CertificateType_DSA_Sign
            , CertificateType_ECDSA_Sign
            ]

instance Arbitrary Handshake where
    arbitrary =
        oneof
            [ arbitrary >>= \ver ->
                ClientHello ver
                    <$> arbitrary
                    <*> arbitrary
                    <*> arbitraryCiphersIDs
                    <*> arbitraryCompressionIDs
                    <*> arbitraryHelloExtensions ver
                    <*> return Nothing
            , arbitrary >>= \ver ->
                ServerHello ver
                    <$> arbitrary
                    <*> arbitrary
                    <*> arbitrary
                    <*> arbitrary
                    <*> arbitraryHelloExtensions ver
            , Certificates . CertificateChain <$> resize 2 (listOf arbitraryX509)
            , pure HelloRequest
            , pure ServerHelloDone
            , ClientKeyXchg . CKX_RSA <$> genByteString 48
            , CertRequest <$> arbitrary <*> arbitrary <*> listOf arbitraryDN
            , CertVerify <$> arbitrary
            , Finished <$> genByteString 12
            ]

instance Arbitrary Handshake13 where
    arbitrary =
        oneof
            [ arbitrary >>= \ver ->
                ClientHello13 ver
                    <$> arbitrary
                    <*> arbitrary
                    <*> arbitraryCiphersIDs
                    <*> arbitraryHelloExtensions ver
            , arbitrary >>= \ver ->
                ServerHello13
                    <$> arbitrary
                    <*> arbitrary
                    <*> arbitrary
                    <*> arbitraryHelloExtensions ver
            , NewSessionTicket13
                <$> arbitrary
                <*> arbitrary
                <*> genByteString 32 -- nonce
                <*> genByteString 32 -- session ID
                <*> arbitrary
            , pure EndOfEarlyData13
            , EncryptedExtensions13 <$> arbitrary
            , CertRequest13
                <$> arbitraryCertReqContext
                <*> arbitrary
            , resize 2 (listOf arbitraryX509) >>= \certs ->
                Certificate13
                    <$> arbitraryCertReqContext
                    <*> return (CertificateChain certs)
                    <*> replicateM (length certs) arbitrary
            , CertVerify13 <$> (head <$> arbitrary) <*> genByteString 32
            , Finished13 <$> genByteString 12
            , KeyUpdate13 <$> elements [UpdateNotRequested, UpdateRequested]
            ]

----------------------------------------------------------------

arbitraryCiphersIDs :: Gen [Word16]
arbitraryCiphersIDs = choose (0, 200) >>= vector

arbitraryCompressionIDs :: Gen [Word8]
arbitraryCompressionIDs = choose (0, 200) >>= vector

someWords8 :: Int -> Gen [Word8]
someWords8 = vector

arbitraryHelloExtensions :: Version -> Gen [ExtensionRaw]
arbitraryHelloExtensions _ver = arbitrary

arbitraryCertReqContext :: Gen B.ByteString
arbitraryCertReqContext = oneof [return B.empty, genByteString 32]

----------------------------------------------------------------

knownCiphers :: [Cipher]
knownCiphers = ciphersuite_all ++ ciphersuite_weak
  where
    ciphersuite_weak =
        [ cipher_null_SHA1
        ]

instance Arbitrary Cipher where
    arbitrary = elements knownCiphers

knownVersions :: [Version]
knownVersions = [TLS13, TLS12]

arbitraryVersions :: Gen [Version]
arbitraryVersions = sublistOf knownVersions

-- for performance reason P521, FFDHE6144, FFDHE8192 are not tested
knownGroups, knownECGroups, knownFFGroups :: [Group]
knownECGroups = [P256, P384, X25519, X448]
knownFFGroups = [FFDHE2048, FFDHE3072, FFDHE4096]
knownGroups = knownECGroups ++ knownFFGroups

defaultECGroup :: Group
defaultECGroup = P256 -- same as defaultECCurve

otherKnownECGroups :: [Group]
otherKnownECGroups = filter (/= defaultECGroup) knownECGroups

instance Arbitrary Group where
    arbitrary = elements knownGroups

instance {-# OVERLAPS #-} Arbitrary [Group] where
    arbitrary = sublistOf knownGroups

isCredentialDSA :: (CertificateChain, PrivKey) -> Bool
isCredentialDSA (_, PrivKeyDSA _) = True
isCredentialDSA _ = False

----------------------------------------------------------------

arbitraryCredentialsOfEachType :: Gen [(CertificateChain, PrivKey)]
arbitraryCredentialsOfEachType = arbitraryCredentialsOfEachType' >>= shuffle

arbitraryCredentialsOfEachType' :: Gen [(CertificateChain, PrivKey)]
arbitraryCredentialsOfEachType' = do
    let (pubKey, privKey) = getGlobalRSAPair
        curveName = defaultECCurve
    (dsaPub, dsaPriv) <- arbitraryDSAPair
    (ecdsaPub, ecdsaPriv) <- arbitraryECDSAPair curveName
    (ed25519Pub, ed25519Priv) <- arbitraryEd25519Pair
    (ed448Pub, ed448Priv) <- arbitraryEd448Pair
    mapM
        ( \(pub, priv) -> do
            cert <- arbitraryX509WithKey (pub, priv)
            return (CertificateChain [cert], priv)
        )
        [ (PubKeyRSA pubKey, PrivKeyRSA privKey)
        , (PubKeyDSA dsaPub, PrivKeyDSA dsaPriv)
        , (toPubKeyEC curveName ecdsaPub, toPrivKeyEC curveName ecdsaPriv)
        , (PubKeyEd25519 ed25519Pub, PrivKeyEd25519 ed25519Priv)
        , (PubKeyEd448 ed448Pub, PrivKeyEd448 ed448Priv)
        ]

arbitraryCredentialsOfEachCurve :: Gen [(CertificateChain, PrivKey)]
arbitraryCredentialsOfEachCurve = arbitraryCredentialsOfEachCurve' >>= shuffle

arbitraryCredentialsOfEachCurve' :: Gen [(CertificateChain, PrivKey)]
arbitraryCredentialsOfEachCurve' = do
    ecdsaPairs <-
        mapM
            ( \curveName -> do
                (ecdsaPub, ecdsaPriv) <- arbitraryECDSAPair curveName
                return (toPubKeyEC curveName ecdsaPub, toPrivKeyEC curveName ecdsaPriv)
            )
            knownECCurves
    (ed25519Pub, ed25519Priv) <- arbitraryEd25519Pair
    (ed448Pub, ed448Priv) <- arbitraryEd448Pair
    mapM
        ( \(pub, priv) -> do
            cert <- arbitraryX509WithKey (pub, priv)
            return (CertificateChain [cert], priv)
        )
        $ [ (PubKeyEd25519 ed25519Pub, PrivKeyEd25519 ed25519Priv)
          , (PubKeyEd448 ed448Pub, PrivKeyEd448 ed448Priv)
          ]
            ++ ecdsaPairs

----------------------------------------------------------------

dhParamsGroup :: DHParams -> Maybe Group
dhParamsGroup params
    | params == ffdhe2048 = Just FFDHE2048
    | params == ffdhe3072 = Just FFDHE3072
    | otherwise = Nothing

isCustomDHParams :: DHParams -> Bool
isCustomDHParams params = params == dhParams512

leafPublicKey :: CertificateChain -> Maybe PubKey
leafPublicKey (CertificateChain []) = Nothing
leafPublicKey (CertificateChain (leaf : _)) = Just (certPubKey $ getCertificate leaf)

isLeafRSA :: Maybe CertificateChain -> Bool
isLeafRSA chain = case chain >>= leafPublicKey of
    Just (PubKeyRSA _) -> True
    _ -> False

arbitraryCipherPair :: Version -> Gen ([Cipher], [Cipher])
arbitraryCipherPair connectVersion = do
    serverCiphers <-
        arbitrary
            `suchThat` (\cs -> or [cipherAllowedForVersion connectVersion x | x <- cs])
    clientCiphers <-
        arbitrary
            `suchThat` ( \cs ->
                            or
                                [ x `elem` serverCiphers
                                    && cipherAllowedForVersion connectVersion x
                                | x <- cs
                                ]
                       )
    return (clientCiphers, serverCiphers)

----------------------------------------------------------------

newtype CSP = CSP (ClientParams, ServerParams) deriving (Show)

instance Arbitrary CSP where
    arbitrary = CSP <$> arbitraryPairParams

arbitraryPairParams :: Gen (ClientParams, ServerParams)
arbitraryPairParams = elements knownVersions >>= arbitraryPairParamsAt

data GGP = GGP [Group] [Group] deriving (Show)

instance Arbitrary GGP where
    arbitrary = arbitraryGroupPair

-- Pair of groups so that at least the default EC group P256 and one FF group
-- are in common.  This makes DHE and ECDHE ciphers always compatible with
-- extension "Supported Elliptic Curves" / "Supported Groups".
arbitraryGroupPair :: Gen GGP
arbitraryGroupPair = do
    (serverECGroups, clientECGroups) <-
        arbitraryGroupPairWith defaultECGroup otherKnownECGroups
    (serverFFGroups, clientFFGroups) <- arbitraryGroupPairFrom knownFFGroups
    serverGroups <- shuffle (serverECGroups ++ serverFFGroups)
    clientGroups <- shuffle (clientECGroups ++ clientFFGroups)
    return $ GGP clientGroups serverGroups
  where
    arbitraryGroupPairFrom list =
        elements list >>= \e ->
            arbitraryGroupPairWith e (filter (/= e) list)
    arbitraryGroupPairWith e es = do
        s <- sublistOf es
        c <- sublistOf es
        return (e : s, e : c)

----------------------------------------------------------------

newtype CSP13 = CSP13 (ClientParams, ServerParams) deriving (Show)

instance Arbitrary CSP13 where
    arbitrary = CSP13 <$> arbitraryPairParams13

arbitraryPairParams13 :: Gen (ClientParams, ServerParams)
arbitraryPairParams13 = arbitraryPairParamsAt TLS13

arbitraryPairParamsAt :: Version -> Gen (ClientParams, ServerParams)
arbitraryPairParamsAt connectVersion = do
    (clientCiphers, serverCiphers) <- arbitraryCipherPair connectVersion
    -- Select version lists containing connectVersion, as well as some other
    -- versions for which we have compatible ciphers.  Criteria about cipher
    -- ensure we can test version downgrade.
    let allowedVersions =
            [ v | v <- knownVersions, or
                                        [ x `elem` serverCiphers
                                            && cipherAllowedForVersion v x
                                        | x <- clientCiphers
                                        ]
            ]
        allowedVersionsFiltered = filter (<= connectVersion) allowedVersions
    -- Server or client is allowed to have versions > connectVersion, but not
    -- both simultaneously.
    filterSrv <- arbitrary
    let (clientAllowedVersions, serverAllowedVersions)
            | filterSrv = (allowedVersions, allowedVersionsFiltered)
            | otherwise = (allowedVersionsFiltered, allowedVersions)
    -- Generate version lists containing less than 127 elements, otherwise the
    -- "supported_versions" extension cannot be correctly serialized
    clientVersions <- listWithOthers connectVersion 126 clientAllowedVersions
    serverVersions <- listWithOthers connectVersion 126 serverAllowedVersions
    arbitraryPairParamsWithVersionsAndCiphers
        (clientVersions, serverVersions)
        (clientCiphers, serverCiphers)
  where
    listWithOthers :: a -> Int -> [a] -> Gen [a]
    listWithOthers fixedElement maxOthers others
        | maxOthers < 1 = return [fixedElement]
        | otherwise = sized $ \n -> do
            num <- choose (0, min n maxOthers)
            pos <- choose (0, num)
            prefix <- vectorOf pos $ elements others
            suffix <- vectorOf (num - pos) $ elements others
            return $ prefix ++ (fixedElement : suffix)

----------------------------------------------------------------

getConnectVersion :: (ClientParams, ServerParams) -> Version
getConnectVersion (cparams, sparams) = maximum (cver `intersect` sver)
  where
    sver = supportedVersions (serverSupported sparams)
    cver = supportedVersions (clientSupported cparams)

isVersionEnabled :: Version -> (ClientParams, ServerParams) -> Bool
isVersionEnabled ver (cparams, sparams) =
    (ver `elem` supportedVersions (serverSupported sparams))
        && (ver `elem` supportedVersions (clientSupported cparams))

arbitraryPairParamsWithVersionsAndCiphers
    :: ([Version], [Version])
    -> ([Cipher], [Cipher])
    -> Gen (ClientParams, ServerParams)
arbitraryPairParamsWithVersionsAndCiphers (clientVersions, serverVersions) (clientCiphers, serverCiphers) = do
    secNeg <- arbitrary
    dhparams <- elements [dhParams512, ffdhe2048, ffdhe3072]

    creds <- arbitraryCredentialsOfEachType
    GGP clientGroups serverGroups <- arbitraryGroupPair
    clientHashSignatures <- arbitrary
    serverHashSignatures <- arbitrary
    let serverState =
            def
                { serverSupported =
                    def
                        { supportedCiphers = serverCiphers
                        , supportedVersions = serverVersions
                        , supportedSecureRenegotiation = secNeg
                        , supportedGroups = serverGroups
                        , supportedHashSignatures = serverHashSignatures
                        }
                , serverDHEParams = Just dhparams
                , serverShared = def{sharedCredentials = Credentials creds}
                }
    let clientState =
            (defaultParamsClient "" B.empty)
                { clientSupported =
                    def
                        { supportedCiphers = clientCiphers
                        , supportedVersions = clientVersions
                        , supportedSecureRenegotiation = secNeg
                        , supportedGroups = clientGroups
                        , supportedHashSignatures = clientHashSignatures
                        }
                , clientShared =
                    def
                        { sharedValidationCache =
                            ValidationCache
                                { cacheAdd = \_ _ _ -> return ()
                                , cacheQuery = \_ _ _ -> return ValidationCachePass
                                }
                        }
                }
    return (clientState, serverState)

arbitraryClientCredential :: Version -> Gen Credential
arbitraryClientCredential _ = arbitraryCredentialsOfEachType' >>= elements

arbitraryRSACredentialWithUsage
    :: [ExtKeyUsageFlag] -> Gen (CertificateChain, PrivKey)
arbitraryRSACredentialWithUsage usageFlags = do
    let (pubKey, privKey) = getGlobalRSAPair
    cert <- arbitraryX509WithKeyAndUsage usageFlags (PubKeyRSA pubKey, ())
    return (CertificateChain [cert], PrivKeyRSA privKey)

arbitraryEMSMode :: Gen (EMSMode, EMSMode)
arbitraryEMSMode = (,) <$> gen <*> gen
  where
    gen = elements [NoEMS, AllowEMS, RequireEMS]

setEMSMode
    :: (EMSMode, EMSMode)
    -> (ClientParams, ServerParams)
    -> (ClientParams, ServerParams)
setEMSMode (cems, sems) (clientParam, serverParam) = (clientParam', serverParam')
  where
    clientParam' =
        clientParam
            { clientSupported =
                (clientSupported clientParam)
                    { supportedExtendedMasterSec = cems
                    }
            }
    serverParam' =
        serverParam
            { serverSupported =
                (serverSupported serverParam)
                    { supportedExtendedMasterSec = sems
                    }
            }

genByteString :: Int -> Gen B.ByteString
genByteString i = B.pack <$> vector i
