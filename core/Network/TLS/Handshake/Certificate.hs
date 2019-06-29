-- |
-- Module      : Network.TLS.Handshake.Certificate
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.Certificate
    ( certificateRejected
    , badCertificate
    , rejectOnException
    , verifyLeafKeyUsage
    , extractCAname
    ) where

import Network.TLS.Context.Internal
import Network.TLS.Struct
import Network.TLS.X509
import Control.Monad.State.Strict
import Control.Exception (SomeException)
import Data.X509 (ExtKeyUsage(..), ExtKeyUsageFlag, extensionGet)

-- on certificate reject, throw an exception with the proper protocol alert error.
certificateRejected :: MonadIO m => CertificateRejectReason -> m a
certificateRejected CertificateRejectRevoked =
    throwCore $ Error_Protocol ("certificate is revoked", True, CertificateRevoked)
certificateRejected CertificateRejectExpired =
    throwCore $ Error_Protocol ("certificate has expired", True, CertificateExpired)
certificateRejected CertificateRejectUnknownCA =
    throwCore $ Error_Protocol ("certificate has unknown CA", True, UnknownCa)
certificateRejected (CertificateRejectOther s) =
    throwCore $ Error_Protocol ("certificate rejected: " ++ s, True, CertificateUnknown)

badCertificate :: MonadIO m => String -> m a
badCertificate msg = throwCore $ Error_Protocol (msg, True, BadCertificate)

rejectOnException :: SomeException -> IO CertificateUsage
rejectOnException e = return $ CertificateUsageReject $ CertificateRejectOther $ show e

verifyLeafKeyUsage :: MonadIO m => [ExtKeyUsageFlag] -> CertificateChain -> m ()
verifyLeafKeyUsage _          (CertificateChain [])         = return ()
verifyLeafKeyUsage validFlags (CertificateChain (signed:_)) =
    unless verified $ badCertificate $
        "certificate is not allowed for any of " ++ show validFlags
  where
    cert     = getCertificate signed
    verified =
        case extensionGet (certExtensions cert) of
            Nothing                          -> True -- unrestricted cert
            Just (ExtKeyUsage flags)         -> any (`elem` validFlags) flags

extractCAname :: SignedCertificate -> DistinguishedName
extractCAname cert = certSubjectDN $ getCertificate cert
