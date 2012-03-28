module Tests.Certificate
        ( arbitraryX509
        , arbitraryX509WithPublicKey
        ) where

import Test.QuickCheck
import qualified Data.Certificate.X509 as X509
import qualified Data.Certificate.X509.Cert as Cert
import Data.Time.Calendar (fromGregorian)
import Data.Time.Clock (secondsToDiffTime)

import Tests.PubKey

arbitraryDN = return []

arbitraryTime = do
        year   <- choose (1951, 2050)
        month  <- choose (1, 12)
        day    <- choose (1, 30)
        hour   <- choose (0, 23)
        minute <- choose (0, 59)
        second <- choose (0, 59)
        z      <- arbitrary
        return (fromGregorian year month day
               , secondsToDiffTime (hour * 3600 + minute * 60 + second)
               , z)

maxSerial = 16777216

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

arbitraryX509WithPublicKey pubKey = do
        cert <- arbitraryX509Cert (X509.PubKeyRSA pubKey)
        sig  <- resize 40 $ listOf1 arbitrary
        let sigalg = X509.SignatureALG X509.HashMD5 X509.PubKeyALG_RSA
        return (X509.X509 cert Nothing Nothing sigalg sig)

arbitraryX509 = do
        let pubKey = fst $ getGlobalRSAPair
        arbitraryX509WithPublicKey pubKey
