-- |
-- Module      : Network.TLS.Extra.Certificate
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Extra.Certificate
    ( certificateChecks
    ) where

import Control.Applicative ((<$>))
import Data.X509
import Data.X509.Validation
import Data.X509.CertificateStore
import Network.TLS (CertificateUsage(..), CertificateRejectReason(..))

-- | Returns 'CertificateUsageAccept' if all the checks pass, or the first
--   failure.
certificateChecks :: Checks -> CertificateStore -> CertificateChain -> IO CertificateUsage
certificateChecks checks store cc = do
    reasons <- validate checks store cc
    return $ case reasons of
                []  -> CertificateUsageAccept
                x:_ -> CertificateUsageReject (toRejectReason x)
  where toRejectReason Expired   = CertificateRejectExpired
        toRejectReason InFuture  = CertificateRejectExpired
        toRejectReason UnknownCA = CertificateRejectUnknownCA
        toRejectReason x         = CertificateRejectOther (show x)
