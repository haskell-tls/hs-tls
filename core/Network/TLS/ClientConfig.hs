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
  -- * Re-exports
  Cipher(..),
  module Network.TLS.Extra.Cipher,
  CertificateStore
) where

import Network.TLS.Parameters (ClientParams(..), defaultParamsClient)
import Network.TLS.Cipher (Cipher(..))
import Network.TLS.Extra.Cipher
import Data.X509.CertificateStore (CertificateStore)

-- | Set ciphers that the client supports.
setCiphers :: ClientParams -> [Cipher] -> ClientParams
setCiphers = undefined

-- | Set CA (Certification Authority) the client trusts. To load the
-- system-wide CA, use 'getSystemCertificateStore' from "System.X509".
setCA :: ClientParams -> CertificateStore -> ClientParams
setCA = undefined
