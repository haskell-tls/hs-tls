-- |
-- Module      : Network.TLS.X509
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- X509 helpers
--
module Network.TLS.X509
    ( CertificateChain(..)
    , Certificate(..)
    , SignedCertificate
    , getCertificate
    , isNullCertificateChain
    , getCertificateChainLeaf
    , getSystemCertificateStore
    , CertificateRejectReason(..)
    , CertificateUsage(..)
    , CertificateStore
    , ValidationCache
    , exceptionValidationCache
    , makeCertificateStore
    , validateDefault
    , FailedReason
    , readCertificateStore
    , readCertificates
    , readKeyFile
    , ServiceID
    , wrapCertificateChecks
    ) where

import Data.X509
import Data.X509.File (readKeyFile, readSignedObject)
import Data.X509.Validation
import Data.X509.CertificateStore
import System.X509 (getSystemCertificateStore)

isNullCertificateChain :: CertificateChain -> Bool
isNullCertificateChain (CertificateChain l) = null l

getCertificateChainLeaf :: CertificateChain -> SignedExact Certificate
getCertificateChainLeaf (CertificateChain [])    = error "empty certificate chain"
getCertificateChainLeaf (CertificateChain (x:_)) = x

-- | Certificate and Chain rejection reason
data CertificateRejectReason =
          CertificateRejectExpired
        | CertificateRejectRevoked
        | CertificateRejectUnknownCA
        | CertificateRejectOther String
        deriving (Show,Eq)

-- | Certificate Usage callback possible returns values.
data CertificateUsage =
          CertificateUsageAccept                         -- ^ usage of certificate accepted
        | CertificateUsageReject CertificateRejectReason -- ^ usage of certificate rejected
        deriving (Show,Eq)

wrapCertificateChecks :: [FailedReason] -> CertificateUsage
wrapCertificateChecks [] = CertificateUsageAccept
wrapCertificateChecks l
    | Expired `elem` l   = CertificateUsageReject   CertificateRejectExpired
    | InFuture `elem` l  = CertificateUsageReject   CertificateRejectExpired
    | UnknownCA `elem` l = CertificateUsageReject   CertificateRejectUnknownCA
    | otherwise          = CertificateUsageReject $ CertificateRejectOther (show l)
