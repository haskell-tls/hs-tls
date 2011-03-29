{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Network.TLS.Extra.Certificate
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Extra.Certificate
	( certificateVerifyChain
	, certificateVerify
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

-- | verify a certificates chain using the system certificates available.
--
-- each certificate of the list is verified against the next certificate, until
-- it can be verified against a system certificate (system certificates are assumed as trusted)
certificateVerifyChain :: [X509] -> IO Bool
certificateVerifyChain l
	| l == []   = return False
	| otherwise = do
		-- find a matching certificate that we trust (== installed on the system)
		found <- SysCert.findCertificate (matchsysX509 $ head l)
		case found of
			Just sysx509 -> certificateVerify (head l) sysx509
			Nothing      -> do
				validChain <- certificateVerify (head l) (head $ tail l)
				if validChain
					then certificateVerifyChain $ tail l
					else return False
	where
		matchsysX509 (X509 cert _ _ _) (X509 syscert _ _ _) = do
			let x = certSubjectDN syscert
			let y = certIssuerDN cert
			x == y

-- | verify a certificate against another one.
-- the first certificate need to be signed by the second one for this function to succeed.
certificateVerify :: X509 -> X509 -> IO Bool
certificateVerify ux509@(X509 _ _ sigalg sig) (X509 scert _ _ _) = do
	let f = verifyF sigalg pk
	case f udata esig of
		Right True -> return True
		_          -> return False
	where
		udata = B.concat $ L.toChunks $ getSigningData ux509
		esig  = B.pack sig
		pk    = certPubKey scert

verifyF :: SignatureALG -> PubKey -> B.ByteString -> B.ByteString -> Either String Bool

verifyF SignatureALG_md2WithRSAEncryption (PubKeyRSA rsak) = rsaVerify MD2.hash asn1 (mkRSA rsak)
	where asn1 = "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10"

verifyF SignatureALG_md5WithRSAEncryption (PubKeyRSA rsak) = rsaVerify MD5.hash asn1 (mkRSA rsak)
	where asn1 = "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10"

verifyF SignatureALG_sha1WithRSAEncryption (PubKeyRSA rsak) = rsaVerify SHA1.hash asn1 (mkRSA rsak)
	where asn1 = "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10"

verifyF SignatureALG_dsaWithSHA1 (PubKeyDSA (pub,p,q,g)) = dsaSHA1Verify pk
	where
		pk        = DSA.PublicKey { DSA.public_params = (p,g,q), DSA.public_y = pub }
			
verifyF _ _ = (\_ _ -> Left "unexpected/wrong signature")

dsaSHA1Verify pk a b = either (Left . show) (Right) $ DSA.verify asig SHA1.hash pk b
	where asig = (0,0) {- FIXME : need to work out how to get R/S from the bytestring a -}

rsaVerify h hdesc pk a b = either (Left . show) (Right) $ RSA.verify h hdesc pk a b
mkRSA (lenmodulus, modulus, e) =
	RSA.PublicKey { RSA.public_sz = lenmodulus, RSA.public_n = modulus, RSA.public_e = e }
