{-# LANGUAGE BangPatterns #-}
module Certificate
    ( arbitraryX509
    , arbitraryX509WithKey
    , simpleCertificate
    , simpleX509
    ) where

import Control.Applicative
import Test.Tasty.QuickCheck
import Data.X509
import Data.Hourglass
import qualified Data.ByteString as B

import PubKey

testExtensionEncode critical ext = ExtensionRaw (extOID ext) critical (extEncode ext)

arbitraryDN = return $ DistinguishedName []

instance Arbitrary Date where
    arbitrary = do
        y <- choose (1971, 2035)
        m <- elements [ January .. December]
        d <- choose (1, 30)
        return $ normalizeDate $ Date y m d

normalizeDate :: Date -> Date
normalizeDate d = timeConvert (timeConvert d :: Elapsed)

instance Arbitrary TimeOfDay where
    arbitrary = do
        h    <- choose (0, 23)
        mi   <- choose (0, 59)
        se   <- choose (0, 59)
        nsec <- return 0
        return $ TimeOfDay (Hours h) (Minutes mi) (Seconds se) nsec

instance Arbitrary DateTime where
    arbitrary = DateTime <$> arbitrary <*> arbitrary

maxSerial = 16777216

arbitraryCertificate pubKey = do
    serial    <- choose (0,maxSerial)
    issuerdn  <- arbitraryDN
    subjectdn <- arbitraryDN
    validity  <- (,) <$> arbitrary <*> arbitrary
    let sigalg = SignatureALG HashSHA1 (pubkeyToAlg pubKey)
    return $ Certificate
            { certVersion      = 3
            , certSerial       = serial
            , certSignatureAlg = sigalg
            , certIssuerDN     = issuerdn
            , certSubjectDN    = subjectdn
            , certValidity     = validity
            , certPubKey       = pubKey
            , certExtensions   = Extensions $ Just
                [ testExtensionEncode True $ ExtKeyUsage [KeyUsage_digitalSignature,KeyUsage_keyEncipherment,KeyUsage_keyCertSign]
                ]
            }

simpleCertificate pubKey =
    Certificate
        { certVersion = 3
        , certSerial = 0
        , certSignatureAlg = SignatureALG HashSHA1 (pubkeyToAlg pubKey)
        , certIssuerDN     = simpleDN
        , certSubjectDN    = simpleDN
        , certValidity     = (time1, time2)
        , certPubKey       = pubKey
        , certExtensions   = Extensions $ Just
                [ testExtensionEncode True $ ExtKeyUsage [KeyUsage_digitalSignature,KeyUsage_keyEncipherment]
                ]
        }
  where time1 = DateTime (Date 1999 January 1) (TimeOfDay 0 0 0 0)
        time2 = DateTime (Date 2049 January 1) (TimeOfDay 0 0 0 0)
        simpleDN = DistinguishedName []

simpleX509 pubKey = do
    let cert = simpleCertificate pubKey
        sig  = replicate 40 1
        sigalg = SignatureALG HashSHA1 (pubkeyToAlg pubKey)
        (signedExact, ()) = objectToSignedExact (\_ -> (B.pack sig,sigalg,())) cert
     in signedExact

arbitraryX509WithKey (pubKey, _) = do
    cert <- arbitraryCertificate pubKey
    sig  <- resize 40 $ listOf1 arbitrary
    let sigalg = SignatureALG HashSHA1 (pubkeyToAlg pubKey)
    let (signedExact, ()) = objectToSignedExact (\(!(_)) -> (B.pack sig,sigalg,())) cert
    return signedExact

arbitraryX509 = do
    let (pubKey, privKey) = getGlobalRSAPair
    arbitraryX509WithKey (PubKeyRSA pubKey, PrivKeyRSA privKey)
