{-# LANGUAGE ScopedTypeVariables #-}
-- |
-- Module      : Network.TLS.Handshake.Certificate
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.Certificate
    ( certificateRejected
    , rejectOnException
    ) where

import Network.TLS.Context
import Network.TLS.Struct
import Control.Monad.State
import Control.Exception (SomeException, AsyncException, Handler(..), throwIO)
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

rejectOnException :: [Handler TLSCertificateUsage]
rejectOnException =
    [Handler $ \(e::AsyncException) -> throwIO e
    ,Handler $ \(e::SomeException) -> return $ CertificateUsageReject $ CertificateRejectOther $ show e]
