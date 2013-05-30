-- |
-- Module      : Network.TLS.Extra.Certificate
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Extra.Certificate
    ( certificateChecks
    , certificateNoChecks
    , defaultChecks
    , Checks(..)
    ) where

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

-- | Accept every certificate chain.
--
-- This function is for debug purpose. TLS is completely unsafe
-- if the certificate have not been checked.
--
-- DO NOT USE in production code.
certificateNoChecks :: CertificateChain -> IO CertificateUsage
certificateNoChecks = return . const CertificateUsageAccept
