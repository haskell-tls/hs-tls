module Certificate
        ( arbitraryX509
        , arbitraryX509WithPublicKey
        ) where

import Test.QuickCheck
import Data.X509
import Data.Time.Calendar (fromGregorian)
import Data.Time.Clock (secondsToDiffTime, UTCTime(..))
import qualified Data.ByteString as B

import PubKey

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
    version   <- choose (1,3)
    serial    <- choose (0,maxSerial)
    issuerdn  <- arbitraryDN
    subjectdn <- arbitraryDN
    time1     <- arbitraryTime
    time2     <- arbitraryTime
    let sigalg = SignatureALG HashMD5 PubKeyALG_RSA
    return $ Certificate
            { certVersion      = version
            , certSerial       = serial
            , certSignatureAlg = sigalg
            , certIssuerDN     = issuerdn
            , certSubjectDN    = subjectdn
            , certValidity     = (time1, time2)
            , certPubKey       = pubKey
            , certExtensions   = Extensions Nothing
            }

{-
arbitraryX509Cert pubKey = do
        version   <- choose (1,3)
        serial    <- choose (0,maxSerial)
        issuerdn  <- arbitraryDN
        subjectdn <- arbitraryDN
        time1     <- arbitraryTime
        time2     <- arbitraryTime
        let sigalg = X509.SignatureALG X509.HashMD5 X509.PubKeyALG_RSA
        return $ Cert.Certificate
                { X509.certVersion      = version
                , X509.certSerial       = serial
                , X509.certSignatureAlg = sigalg
                , X509.certIssuerDN     = issuerdn
                , X509.certSubjectDN    = subjectdn
                , X509.certValidity     = (time1, time2)
                , X509.certPubKey       = pubKey
                , X509.certExtensions   = Nothing
                }
-}

arbitraryX509WithPublicKey pubKey = do
        cert <- arbitraryCertificate (PubKeyRSA pubKey)
        sig  <- resize 40 $ listOf1 arbitrary
        let sigalg = SignatureALG HashMD5 PubKeyALG_RSA
        let (signedExact, ()) = objectToSignedExact (\_ -> (B.pack sig,sigalg,())) cert
        return signedExact

arbitraryX509 = do
        let pubKey = fst $ getGlobalRSAPair
        arbitraryX509WithPublicKey pubKey
