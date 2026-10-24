module Network.TLS.Handshake.Certificate (
    certificateRejected,
    badCertificate,
    rejectOnException,
    verifyLeafKeyUsage,
    verifyLeafKeyUsagePurpose,
    verifyLeafKeySize,
    extractCAname,
) where

import qualified Control.Exception as E
import Control.Monad (unless)
import Control.Monad.State.Strict
import qualified Crypto.PubKey.RSA as RSA
import Data.ASN1.Types (asn1CharacterToString)
import Data.ByteArray.Encoding (Base (Base64), convertToBase)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import Data.List (intercalate, isInfixOf)
import Data.X509 (
    ExtExtendedKeyUsage (..),
    ExtKeyUsage (..),
    ExtKeyUsageFlag,
    ExtKeyUsagePurpose (..),
    PubKey (PubKeyRSA),
    encodeSignedObject,
    extensionGet,
    getDistinguishedElements,
 )

import Network.TLS.Context.Internal
import Network.TLS.Parameters
import Network.TLS.Struct
import Network.TLS.X509

-- | On certificate reject, throw an exception with the proper protocol alert
-- error.  The message carries the reasons of the validation and the subject
-- and issuer of the leaf; the whole chain goes to 'debugError' in PEM.
certificateRejected
    :: MonadIO m
    => Context -> [FailedReason] -> CertificateChain -> CertificateRejectReason -> m a
certificateRejected ctx reasons cc reason = do
    let ~pem = chainPEM cc
    liftIO $ debugError (ctxDebug ctx) $ msg ++ details ++ "\n" ++ pem
    throwCore $ Error_Protocol (msg ++ details) alert
  where
    (msg, alert) = case reason of
        CertificateRejectRevoked -> ("certificate is revoked", CertificateRevoked)
        CertificateRejectExpired -> ("certificate has expired", CertificateExpired)
        CertificateRejectUnknownCA -> ("certificate has unknown CA", UnknownCa)
        CertificateRejectAbsent -> ("certificate is missing", CertificateRequired)
        CertificateRejectOther s -> ("certificate rejected: " ++ s, CertificateUnknown)
    -- wrapCertificateChecks may have put the reasons in the message already
    details =
        concatMap ("; " ++) $
            [rs | not (null reasons), not (rs `isInfixOf` msg)] ++ leafSummary cc
    rs = show reasons

-- | The subject and issuer of the leaf certificate.
leafSummary :: CertificateChain -> [String]
leafSummary (CertificateChain []) = []
leafSummary (CertificateChain (signed : _)) =
    [ "subject: " ++ showDN (certSubjectDN cert)
    , "issuer: " ++ showDN (certIssuerDN cert)
    ]
  where
    cert = getCertificate signed

showDN :: DistinguishedName -> String
showDN dn =
    intercalate
        ", "
        [name oid ++ "=" ++ value cs | (oid, cs) <- getDistinguishedElements dn]
  where
    name oid = maybe (intercalate "." $ map show oid) id $ lookup oid names
    value = maybe "?" id . asn1CharacterToString
    names =
        [ ([2, 5, 4, 3], "CN")
        , ([2, 5, 4, 6], "C")
        , ([2, 5, 4, 7], "L")
        , ([2, 5, 4, 8], "ST")
        , ([2, 5, 4, 10], "O")
        , ([2, 5, 4, 11], "OU")
        ]

-- | The certificates of the chain in PEM, leaf first.
chainPEM :: CertificateChain -> String
chainPEM (CertificateChain certs) = concatMap pem certs
  where
    pem signed =
        "-----BEGIN CERTIFICATE-----\n"
            ++ concatMap
                ((++ "\n") . C8.unpack)
                (lines64 $ convertToBase Base64 $ encodeSignedObject signed)
            ++ "-----END CERTIFICATE-----\n"
    lines64 bs
        | B.null bs = []
        | otherwise = let (l, r) = B.splitAt 64 bs in l : lines64 r

badCertificate :: MonadIO m => String -> m a
badCertificate msg = throwCore $ Error_Protocol msg BadCertificate

rejectOnException :: E.SomeException -> IO CertificateUsage
rejectOnException e = return $ CertificateUsageReject $ CertificateRejectOther $ show e

verifyLeafKeyUsage :: MonadIO m => [ExtKeyUsageFlag] -> CertificateChain -> m ()
verifyLeafKeyUsage _ (CertificateChain []) = return ()
verifyLeafKeyUsage validFlags (CertificateChain (signed : _)) =
    unless verified $
        badCertificate $
            "certificate is not allowed for any of " ++ show validFlags
  where
    cert = getCertificate signed
    verified =
        case extensionGet (certExtensions cert) of
            Nothing -> True -- unrestricted cert
            Just (ExtKeyUsage flags) -> any (`elem` validFlags) flags

verifyLeafKeyUsagePurpose
    :: MonadIO m => ExtKeyUsagePurpose -> CertificateChain -> m ()
verifyLeafKeyUsagePurpose _ (CertificateChain []) = return ()
verifyLeafKeyUsagePurpose validPurpose (CertificateChain (signed : _)) =
    unless verified $
        badCertificate $
            "certificate is not allowed for " ++ show validPurpose
  where
    cert = getCertificate signed
    verified = case extensionGet (certExtensions cert) of
        Nothing -> True
        Just (ExtExtendedKeyUsage purposes) -> validPurpose `elem` purposes

-- | The RSA key of the peer's leaf certificate is to be at least
-- 'supportedMinRSAKeySize' bits.  The keys of the rest of the chain are left
-- to the validation of the chain.
verifyLeafKeySize :: MonadIO m => Supported -> CertificateChain -> m ()
verifyLeafKeySize _ (CertificateChain []) = return ()
verifyLeafKeySize supported (CertificateChain (signed : _)) =
    case certPubKey $ getCertificate signed of
        PubKeyRSA pk
            | bits < minBits ->
                badCertificate $
                    "RSA key of " ++ show bits ++ " bits is shorter than " ++ show minBits
          where
            bits = RSA.public_size pk * 8
        _ -> return ()
  where
    minBits = supportedMinRSAKeySize supported

extractCAname :: SignedCertificate -> DistinguishedName
extractCAname cert = certSubjectDN $ getCertificate cert
