{-# LANGUAGE BangPatterns #-}
module Certificate
    ( arbitraryX509
    , arbitraryX509WithKey
    , simpleCertificate
    , simpleX509
    ) where

import Test.QuickCheck
import Data.X509
import Data.Time.Calendar (fromGregorian)
import Data.Time.Clock (secondsToDiffTime, UTCTime(..))
import qualified Data.ByteString as B

import PubKey

testExtensionEncode critical ext = ExtensionRaw (extOID ext) critical (extEncode ext)

arbitraryDN = return $ DistinguishedName []

arbitraryTime = do
    year   <- choose (1951, 2050)
    month  <- choose (1, 12)
    day    <- choose (1, 30)
    hour   <- choose (0, 23)
    minute <- choose (0, 59)
    second <- choose (0, 59)
    --z      <- arbitrary
    return $ UTCTime (fromGregorian year month day) (secondsToDiffTime (hour * 3600 + minute * 60 + second))

maxSerial = 16777216

arbitraryCertificate pubKey = do
    serial    <- choose (0,maxSerial)
    issuerdn  <- arbitraryDN
    subjectdn <- arbitraryDN
    time1     <- arbitraryTime
    time2     <- arbitraryTime
    let sigalg = SignatureALG HashSHA1 (pubkeyToAlg pubKey)
    return $ Certificate
            { certVersion      = 3
            , certSerial       = serial
            , certSignatureAlg = sigalg
            , certIssuerDN     = issuerdn
            , certSubjectDN    = subjectdn
            , certValidity     = (time1, time2)
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
  where time1 = UTCTime (fromGregorian 1999 1 1) 0
        time2 = UTCTime (fromGregorian 2901 1 1) 0
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
