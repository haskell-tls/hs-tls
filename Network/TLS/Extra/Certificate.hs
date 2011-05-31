{-# LANGUAGE OverloadedStrings, CPP #-}
-- |
-- Module      : Network.TLS.Extra.Certificate
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Extra.Certificate
	( certificateChecks
	, certificateVerifyChain
	, certificateVerifyAgainst
	, certificateSelfSigned
	, certificateVerifyDomain
	, certificateVerifyValidity
	, certificateFingerprint
	) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Certificate.X509
import System.Certificate.X509 as SysCert

-- for signing/verifying certificate
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.MD2 as MD2
import qualified Crypto.Hash.MD5 as MD5
import qualified Crypto.Cipher.RSA as RSA
import qualified Crypto.Cipher.DSA as DSA

import Data.Certificate.X509Cert (oidCommonName)
import Network.TLS (TLSCertificateUsage(..), TLSCertificateRejectReason(..))

import Data.Time.Calendar
import Data.List (find)

-- | combine many certificates checking function together.
-- if one check fail, the whole sequence of checking is cuted short and return the
-- reject reason.
certificateChecks :: [ [X509] -> IO TLSCertificateUsage ] -> [X509] -> IO TLSCertificateUsage
certificateChecks checks x509s = do
	r <- sequence $ map (\c -> c x509s) checks
	return $ maybe CertificateUsageAccept id $ find ((/=) CertificateUsageAccept) r

#if defined(NOCERTVERIFY)

# warning "********certificate verify chain doesn't yet work on your platform *************"
# warning "********please consider contributing to the certificate to fix this issue *************"
# warning "********getting trusted system certificate is platform dependant *************"

{- on windows and OSX, the trusted certificates are not yet accessible,
 - for now, print a big fat warning (better than nothing) and returns true  -}
certificateVerifyChain :: [X509] -> IO TLSCertificateUsage
certificateVerifyChain _ = do
	putStrLn "****************** certificate verify chain doesn't yet work on your platform **********************"
	putStrLn "please consider contributing to the certificate package to fix this issue"
	return True

#else
-- | verify a certificates chain using the system certificates available.
--
-- each certificate of the list is verified against the next certificate, until
-- it can be verified against a system certificate (system certificates are assumed as trusted)
--
-- This helper only check that the chain of certificate is valid, which means that each items
-- received are signed by the next one, or by a system certificate. Some extra checks need to
-- be done at the user level so that the certificate chain received make sense in the context.
--
-- for example for HTTP, the user should typically verify the certificate subject match the URL
-- of connection.
--
-- TODO: verify validity, check revocation list if any, add optional user output to know
-- the rejection reason.
certificateVerifyChain :: [X509] -> IO TLSCertificateUsage
certificateVerifyChain l
	| l == []   = return $ CertificateUsageReject CertificateRejectUnknownCA
	| otherwise = do
		-- find a matching certificate that we trust (== installed on the system)
		found <- SysCert.findCertificate (matchsysX509 $ head l)
		case found of
			Just sysx509 -> do
				validChain <- certificateVerifyAgainst (head l) sysx509
				if validChain
					then return CertificateUsageAccept
					else return $ CertificateUsageReject (CertificateRejectOther "chain doesn't match each other")
			Nothing      -> do
				validChain <- certificateVerifyAgainst (head l) (head $ tail l)
				if validChain
					then certificateVerifyChain $ tail l
					else return $ CertificateUsageReject (CertificateRejectOther "chain doesn't match each other")
	where
		matchsysX509 (X509 cert _ _ _ _) (X509 syscert _ _ _ _) = do
			let x = certSubjectDN syscert
			let y = certIssuerDN cert
			x == y
#endif

-- | verify a certificate against another one.
-- the first certificate need to be signed by the second one for this function to succeed.
certificateVerifyAgainst :: X509 -> X509 -> IO Bool
certificateVerifyAgainst ux509@(X509 _ _ _ sigalg sig) (X509 scert _ _ _ _) = do
	let f = verifyF sigalg pk
	case f udata esig of
		Right True -> return True
		_          -> return False
	where
		udata = B.concat $ L.toChunks $ getSigningData ux509
		esig  = B.pack sig
		pk    = certPubKey scert

-- | returns if this certificate is self signed.
certificateSelfSigned :: X509 -> Bool
certificateSelfSigned x509 = certMatchDN x509 x509

certMatchDN :: X509 -> X509 -> Bool
certMatchDN (X509 testedCert _ _ _ _) (X509 issuerCert _ _ _ _) =
	certSubjectDN issuerCert == certIssuerDN testedCert

verifyF :: SignatureALG -> PubKey -> B.ByteString -> B.ByteString -> Either String Bool

-- md[245]WithRSAEncryption:
--
--   pkcs-1 OBJECT IDENTIFIER ::= { iso(1) member-body(2) US(840) rsadsi(113549) pkcs(1) 1 }
--   rsaEncryption OBJECT IDENTIFIER ::= { pkcs-1 1 }
--   md2WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 2 }
--   md4WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 3 }
--   md5WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 4 }
verifyF SignatureALG_md2WithRSAEncryption (PubKeyRSA rsak) = rsaVerify MD2.hash asn1 (mkRSA rsak)
	where asn1 = "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x02\x10"

verifyF SignatureALG_md5WithRSAEncryption (PubKeyRSA rsak) = rsaVerify MD5.hash asn1 (mkRSA rsak)
	where asn1 = "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10"

verifyF SignatureALG_sha1WithRSAEncryption (PubKeyRSA rsak) = rsaVerify SHA1.hash asn1 (mkRSA rsak)
	where asn1 = "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"

verifyF SignatureALG_dsaWithSHA1 (PubKeyDSA (pub,p,q,g)) = dsaSHA1Verify pk
	where
		pk        = DSA.PublicKey { DSA.public_params = (p,g,q), DSA.public_y = pub }
			
verifyF _ _ = (\_ _ -> Left "unexpected/wrong signature")

dsaSHA1Verify pk _ b = either (Left . show) (Right) $ DSA.verify asig SHA1.hash pk b
	where asig = (0,0) {- FIXME : need to work out how to get R/S from the bytestring a -}

rsaVerify h hdesc pk a b = either (Left . show) (Right) $ RSA.verify h hdesc pk a b

mkRSA (lenmodulus, modulus, e) =
	RSA.PublicKey { RSA.public_sz = lenmodulus, RSA.public_n = modulus, RSA.public_e = e }

-- | Verify that the given certificate chain is application to the given fully qualified host name.
certificateVerifyDomain :: String -> [X509] -> TLSCertificateUsage
certificateVerifyDomain _      []                  = CertificateUsageReject (CertificateRejectOther "empty list")
certificateVerifyDomain fqhn (X509 cert _ _ _ _:_) =
	case lookup oidCommonName $ certSubjectDN cert of
		Nothing       -> rejectMisc "no commonname OID in certificate cannot match to FQDN"
		Just (_, val) -> matchDomain (splitDot val)
	where
		matchDomain l
			| length (filter (== "") l) > 0 = rejectMisc "commonname OID got empty subdomain"
			| head l == "*"                 = wildcardMatch (reverse $ drop 1 l)
			| otherwise                     = if l == splitDot fqhn
				then CertificateUsageAccept
				else rejectMisc "FQDN and common name OID do not match"

		-- only 1 wildcard is valid, and if multiples are present
		-- they won't have a wildcard meaning but will be match as normal star
		-- character to the fqhn and inevitably will fail.
		wildcardMatch l
			-- <star>.com or <star> is always invalid
			| length l < 2                         = rejectMisc "commonname OID wildcard match too widely"
			-- <star>.com.<country> is always invalid
			| length (head l) <= 2 && length (head $ drop 1 l) <= 3 && length l < 3 = rejectMisc "commonname OID wildcard match too widely"
			| otherwise                            =
				if l == take (length l) (reverse $ splitDot fqhn)
					then CertificateUsageAccept
					else rejectMisc "FQDN and common name OID do not match"

		splitDot :: String -> [String]
		splitDot [] = [""]
		splitDot x  =
			let (y, z) = break (== '.') x in
			y : (if z == "" then [] else splitDot $ drop 1 z)

		rejectMisc s = CertificateUsageReject (CertificateRejectOther s)

-- | Verify certificate validity period that need to between the bounds of the certificate.
-- TODO: maybe should verify whole chain.
certificateVerifyValidity :: Day -> [X509] -> TLSCertificateUsage
certificateVerifyValidity _ []                         = CertificateUsageReject $ CertificateRejectOther "empty list"
certificateVerifyValidity ctime (X509 cert _ _ _ _ :_) =
	let ((beforeDay,_,_) , (afterDay,_,_)) = certValidity cert in
	if beforeDay < ctime && ctime <= afterDay
		then CertificateUsageAccept
		else CertificateUsageReject CertificateRejectExpired

-- | hash the certificate signing data using the supplied hash function.
certificateFingerprint :: (L.ByteString -> B.ByteString) -> X509 -> B.ByteString
certificateFingerprint hash x509 = hash $ getSigningData x509
