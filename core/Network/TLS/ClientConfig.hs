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
  -- * Re-exports (Cipher)
  Cipher(..),
  module Network.TLS.Extra.Cipher,
  -- * Re-exports (Certificates)
  CertificateStore,
  makeCertificateStore, listCertificates,
  SignedCertificate,
  readSignedObject
) where

import Network.TLS.Parameters (ClientParams(..), defaultParamsClient, Shared(..), Supported(..))
import Network.TLS.Cipher (Cipher(..))
import Network.TLS.Extra.Cipher
import Data.X509.CertificateStore (CertificateStore, makeCertificateStore, listCertificates)
import Data.X509.File (readSignedObject)
import Data.X509 (SignedCertificate)

-- | Set ciphers that the client supports. Normally, you can just set
-- 'ciphersuite_all', which is exported by this module.
setCiphers :: ClientParams -> [Cipher] -> ClientParams
setCiphers cp ciphers = cp { clientSupported = (clientSupported cp) { supportedCiphers = ciphers } }

-- | Set CA (Certification Authority) the client trusts.
-- 
-- To load the system-wide CA, use
-- 'System.X509.getSystemCertificateStore'.
--
-- To load CA certificates from files, use 'readSignedObject' and
-- 'makeCertificateStore', which are exported by this module.
setCA :: ClientParams -> CertificateStore -> ClientParams
setCA cp certs = cp { clientShared = (clientShared cp) { sharedCAStore = certs } }
