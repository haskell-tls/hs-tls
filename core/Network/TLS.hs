-- |
-- Module      : Network.TLS
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS
    (
    -- * Context configuration
      Params(..)
    , RoleParams(..)
    , ClientParams(..)
    , ServerParams(..)
    , updateClientParams
    , updateServerParams
    , Logging(..)
    , Measurement(..)
    , CertificateUsage(..)
    , CertificateRejectReason(..)
    , defaultParamsClient
    , defaultParamsServer
    , defaultLogging
    , MaxFragmentEnum(..)
    , HashAndSignatureAlgorithm
    , HashAlgorithm(..)
    , SignatureAlgorithm(..)
    , CertificateType(..)

    -- * raw types
    , ProtocolType(..)
    , Header(..)

    -- * Session
    , SessionID
    , SessionData(..)
    , SessionManager(..)
    , NoSessionManager(..)
    , setSessionManager

    -- * Backend abstraction
    , Backend(..)

    -- * Context object
    , Context
    , ctxConnection

    -- * Creating a context
    , contextNew
    , contextNewOnHandle
    , contextFlush
    , contextClose

    -- * deprecated type aliases
    , TLSParams
    , TLSLogging
    , TLSCertificateUsage
    , TLSCertificateRejectReason
    , TLSCtx

    -- * deprecated values
    , defaultParams

    -- * Initialisation and Termination of context
    , bye
    , handshake

    -- * Next Protocol Negotiation
    , getNegotiatedProtocol

    -- * High level API
    , sendData
    , recvData
    , recvData'

    -- * Crypto Key
    , PrivateKey(..)

    -- * Compressions & Predefined compressions
    , CompressionID
    , CompressionC(..)
    , Compression(..)
    , nullCompression

    -- * Ciphers & Predefined ciphers
    , CipherID
    , Cipher(..)
    , Hash(..)
    , Bulk(..)
    , BulkFunctions(..)
    , CipherKeyExchangeType(..)
    , Key
    , IV

    -- * Versions
    , Version(..)

    -- * Errors
    , TLSError(..)
    , KxError(..)
    , AlertDescription(..)

    -- * Exceptions
    , HandshakeFailed(..)
    , ConnectionNotEstablished(..)
    ) where

import Network.TLS.Types (CompressionID, CipherID)
import Network.TLS.Struct (Version(..), TLSError(..), HashAndSignatureAlgorithm, HashAlgorithm(..), SignatureAlgorithm(..), Header(..), ProtocolType(..), CertificateType(..), AlertDescription(..))
import Network.TLS.Crypto (PrivateKey(..), KxError(..))
import Network.TLS.Cipher (Cipher(..), Bulk(..), BulkFunctions(..), Hash(..), CipherKeyExchangeType(..), Key, IV)
import Network.TLS.Compression (CompressionC(..), Compression(..), nullCompression)
import Network.TLS.Context
import Network.TLS.Core
import Network.TLS.Session
