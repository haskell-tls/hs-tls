{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Certificate (
    arbitraryX509,
    arbitraryX509WithKey,
    arbitraryX509WithKeyAndUsage,
    arbitraryDN,
    getSignatureALG,
    toPubKeyEC,
    toPrivKeyEC,
) where

import Crypto.Number.Serialize (i2ospOf_)
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Types as ECC
import Data.ASN1.OID
import qualified Data.ByteString as B
import Data.Hourglass
import Data.X509
import Test.QuickCheck

import PubKey

arbitraryDN :: Gen DistinguishedName
arbitraryDN = return $ DistinguishedName []

instance Arbitrary Date where
    arbitrary = do
        y <- choose (1971, 2035)
        m <- elements [January .. December]
        d <- choose (1, 30)
        return $ normalizeDate $ Date y m d

normalizeDate :: Date -> Date
normalizeDate d = timeConvert (timeConvert d :: Elapsed)

instance Arbitrary TimeOfDay where
    arbitrary = do
        h <- choose (0, 23)
        mi <- choose (0, 59)
        se <- choose (0, 59)
        let nsec = 0
        return $ TimeOfDay (Hours h) (Minutes mi) (Seconds se) nsec

instance Arbitrary DateTime where
    arbitrary = DateTime <$> arbitrary <*> arbitrary

maxSerial :: Integer
maxSerial = 16777216

arbitraryCertificate :: [ExtKeyUsageFlag] -> PubKey -> Gen Certificate
arbitraryCertificate usageFlags pubKey = do
    serial <- choose (0, maxSerial)
    subjectdn <- arbitraryDN
    validity <- (,) <$> arbitrary <*> arbitrary
    let sigalg = getSignatureALG pubKey
    return $
        Certificate
            { certVersion = 3
            , certSerial = serial
            , certSignatureAlg = sigalg
            , certIssuerDN = issuerdn
            , certSubjectDN = subjectdn
            , certValidity = validity
            , certPubKey = pubKey
            , certExtensions =
                Extensions $
                    Just
                        [ extensionEncode True $ ExtKeyUsage usageFlags
                        ]
            }
  where
    issuerdn = DistinguishedName [(getObjectID DnCommonName, "Root CA")]


arbitraryX509WithKey :: (PubKey, t) -> Gen SignedCertificate
arbitraryX509WithKey = arbitraryX509WithKeyAndUsage knownKeyUsage

arbitraryX509WithKeyAndUsage
    :: [ExtKeyUsageFlag] -> (PubKey, t) -> Gen SignedCertificate
arbitraryX509WithKeyAndUsage usageFlags (pubKey, _) = do
    cert <- arbitraryCertificate usageFlags pubKey
    sig <- resize 40 $ listOf1 arbitrary
    let sigalg = getSignatureALG pubKey
    let (signedExact, ()) = objectToSignedExact (\_ -> (B.pack sig, sigalg, ())) cert
    return signedExact

arbitraryX509 :: Gen SignedCertificate
arbitraryX509 = do
    let (pubKey, privKey) = getGlobalRSAPair
    arbitraryX509WithKey (PubKeyRSA pubKey, PrivKeyRSA privKey)

instance {-# OVERLAPS #-} Arbitrary [ExtKeyUsageFlag] where
    arbitrary = sublistOf knownKeyUsage

knownKeyUsage :: [ExtKeyUsageFlag]
knownKeyUsage =
    [ KeyUsage_digitalSignature
    , KeyUsage_keyEncipherment
    , KeyUsage_keyAgreement
    ]

getSignatureALG :: PubKey -> SignatureALG
getSignatureALG (PubKeyRSA _) = SignatureALG HashSHA1 PubKeyALG_RSA
getSignatureALG (PubKeyDSA _) = SignatureALG HashSHA1 PubKeyALG_DSA
getSignatureALG (PubKeyEC _) = SignatureALG HashSHA256 PubKeyALG_EC
getSignatureALG (PubKeyEd25519 _) = SignatureALG_IntrinsicHash PubKeyALG_Ed25519
getSignatureALG (PubKeyEd448 _) = SignatureALG_IntrinsicHash PubKeyALG_Ed448
getSignatureALG pubKey =
    error $ "getSignatureALG: unsupported public key: " ++ show pubKey

toPubKeyEC :: ECC.CurveName -> ECDSA.PublicKey -> PubKey
toPubKeyEC curveName key =
    let (x, y) = fromPoint $ ECDSA.public_q key
        pub = SerializedPoint bs
        bs = B.cons 4 (i2ospOf_ bytes x `B.append` i2ospOf_ bytes y)
        bits = ECC.curveSizeBits (ECC.getCurveByName curveName)
        bytes = (bits + 7) `div` 8
     in PubKeyEC (PubKeyEC_Named curveName pub)

toPrivKeyEC :: ECC.CurveName -> ECDSA.PrivateKey -> PrivKey
toPrivKeyEC curveName key =
    let priv = ECDSA.private_d key
     in PrivKeyEC (PrivKeyEC_Named curveName priv)

fromPoint :: ECC.Point -> (Integer, Integer)
fromPoint (ECC.Point x y) = (x, y)
fromPoint _ = error "fromPoint"
