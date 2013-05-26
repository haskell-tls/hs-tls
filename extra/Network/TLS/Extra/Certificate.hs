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
    ) where

import Control.Applicative ((<$>))
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.X509
import Data.X509.Validation
import Data.X509.CertificateStore

import Network.TLS (CertificateUsage(..), CertificateRejectReason(..))

import Data.Time.Calendar
import Data.List (find)
import Data.Maybe (fromMaybe)

-- | Returns 'CertificateUsageAccept' if all the checks pass, or the first
--   failure.
certificateChecks :: Checks -> CertificateChain -> IO CertificateUsage
certificateChecks checks store cc = do
    reasons <- validate checks store cc
    return $ case reasons of
                [] -> CertificateUsageAccept
                _  -> CertificateUsageReject
