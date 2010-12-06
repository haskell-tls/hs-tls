module Tests.Certificate
	( arbitraryX509
	) where

import Test.QuickCheck
import qualified Data.Certificate.X509 as X509
import Control.Monad

readableChar :: Gen Char
readableChar = elements (['a'..'z'] ++ ['A'..'Z'] ++ ['0'..'9'])

arbitraryMaybeString = do
	x <- choose (0,3) :: Gen Int
	case x of
		0 -> return Nothing
		_ -> liftM Just (resize 10 $ listOf1 readableChar)

arbitraryDN = liftM5 X509.CertificateDN
		arbitraryMaybeString -- common name
		arbitraryMaybeString -- country of issuance
		arbitraryMaybeString -- organization
		arbitraryMaybeString -- organizationUnit
		(return [])

arbitraryTime = do
	year   <- choose (1951, 2050)
	month  <- choose (1, 12)
	day    <- choose (1, 30)
	hour   <- choose (0, 23)
	minute <- choose (0, 59)
	second <- choose (0, 59)
	z      <- arbitrary
	return (year, month, day, hour, minute, second, z)

arbitraryX509 pubKey@(X509.PubKey alg _) = do
	version   <- arbitrary
	serial    <- arbitrary
	issuerdn  <- arbitraryDN
	subjectdn <- arbitraryDN
	time1     <- arbitraryTime
	time2     <- arbitraryTime
	sig       <- resize 40 $ listOf1 arbitrary
	return $ X509.Certificate
		{ X509.certVersion      = version
		, X509.certSerial       = serial
		, X509.certSignatureAlg = alg
		, X509.certIssuerDN     = issuerdn
		, X509.certSubjectDN    = subjectdn
		, X509.certValidity     = (time1, time2)
		, X509.certPubKey       = pubKey
		, X509.certExtensions   = Nothing
		, X509.certSignature    = Just (alg, sig)
		, X509.certOthers       = []
		}
