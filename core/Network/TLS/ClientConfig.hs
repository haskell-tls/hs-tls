-- |
-- Module      : Network.TLS.ClientConfig
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>, Toshio Ito <debug.ito@gmail.com>
-- Stability   : experimental
-- Portability : unknown
-- 
-- This module defines and exports functions useful to configure 'ClientParams'.
module Network.TLS.ClientConfig (
  -- * The ClientParams
  ClientParams(..),
  -- * Constructors and setters
  defaultParamsClient,
  setCiphers,
  setCA,
  -- * Ciphers
  Cipher,
  module Network.TLS.Extra.Cipher,
  -- * Certificates
  CertificateStore,
  readCertificateStore,
  makeCertificateStore, listCertificates,
  SignedCertificate,
  readSignedObject,
  -- * Server validator
  ServerValidator
) where

import Network.TLS.Parameters (ClientParams(..), defaultParamsClient, Shared(..), Supported(..))
import Network.TLS.Cipher (Cipher(..))
import Network.TLS.Extra.Cipher
import Data.X509 (SignedCertificate, CertificateChain)
import Data.X509.CertificateStore (CertificateStore, makeCertificateStore, listCertificates)
import Data.X509.File (readSignedObject)
import Data.X509.Validation (ValidationCache, ServiceID, FailedReason)

-- | Set ciphers that the client supports. Normally, you can just set
-- 'ciphersuite_all', which is exported by this module.
setCiphers :: [Cipher] -> ClientParams -> ClientParams
setCiphers ciphers cp = cp { clientSupported = (clientSupported cp) { supportedCiphers = ciphers } }

-- | Set CA (Certification Authority) the client trusts.
-- 
-- To load the system-wide CA, use
-- 'System.X509.getSystemCertificateStore'.  To load CA certificates
-- from files, use 'readCertificateStore'.
--
-- Because 'CertificateStore' is a "Monoid", you can 'mappend' them.
setCA :: CertificateStore -> ClientParams -> ClientParams
setCA certs cp = cp { clientShared = (clientShared cp) { sharedCAStore = certs } }

-- | Read a list of certificate files to create a 'CertificateStore'.
readCertificateStore :: [FilePath] -> IO CertificateStore
readCertificateStore files = fmap (makeCertificateStore . concat) $ mapM readSignedObject files

-- | An action to validate the TLS server.
type ServerValidator = CertificateStore -> ValidationCache -> ServiceID -> CertificateChain -> IO [FailedReason]
