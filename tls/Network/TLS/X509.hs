-- | X509 helpers
module Network.TLS.X509 (
    CertificateChain (..),
    Certificate (..),
    SignedCertificate,
    getCertificate,
    isNullCertificateChain,
    getCertificateChainLeaf,
    CertificateRejectReason (..),
    CertificateUsage (..),
    CertificateStore,
    ValidationCache,
    defaultValidationCache,
    exceptionValidationCache,
    validateDefault,
    FailedReason,
    ServiceID,
    wrapCertificateChecks,
    pubkeyType,
    validateClientCertificate,
) where

import Data.X509
import Data.X509.CertificateStore
import Data.X509.Validation

isNullCertificateChain :: CertificateChain -> Bool
isNullCertificateChain (CertificateChain l) = null l

getCertificateChainLeaf :: CertificateChain -> SignedExact Certificate
getCertificateChainLeaf (CertificateChain []) = error "empty certificate chain"
getCertificateChainLeaf (CertificateChain (x : _)) = x

-- | Certificate and Chain rejection reason
data CertificateRejectReason
    = CertificateRejectExpired
    | CertificateRejectRevoked
    | CertificateRejectUnknownCA
    | CertificateRejectAbsent
    | CertificateRejectOther String
    deriving (Show, Eq)

-- | Certificate Usage callback possible returns values.
data CertificateUsage
    = -- | usage of certificate accepted
      CertificateUsageAccept
    | -- | usage of certificate rejected
      CertificateUsageReject CertificateRejectReason
    deriving (Show, Eq)

wrapCertificateChecks :: [FailedReason] -> CertificateUsage
wrapCertificateChecks [] = CertificateUsageAccept
wrapCertificateChecks l
    | Expired `elem` l = CertificateUsageReject CertificateRejectExpired
    | InFuture `elem` l = CertificateUsageReject CertificateRejectExpired
    | UnknownCA `elem` l = CertificateUsageReject CertificateRejectUnknownCA
    | SelfSigned `elem` l = CertificateUsageReject CertificateRejectUnknownCA
    | EmptyChain `elem` l = CertificateUsageReject CertificateRejectAbsent
    | otherwise = CertificateUsageReject $ CertificateRejectOther (show l)

pubkeyType :: PubKey -> String
pubkeyType = show . pubkeyToAlg

validateClientCertificate
    :: CertificateStore
    -> ValidationCache
    -> CertificateChain
    -> IO CertificateUsage
validateClientCertificate store cache cc =
    wrapCertificateChecks
        <$> validate
            HashSHA256
            defaultHooks
            defaultChecks{checkFQHN = False}
            store
            cache
            ("", mempty)
            cc
