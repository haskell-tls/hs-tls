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
    , ClientCertParamsClient(..)
    , ClientCertParamsServer(..)
    , RoleParams(..)
    , ClientParams(..)
    , ServerParams(..)
    , updateClientParams
    , updateServerParams
    , Logging(..)
    , CertificateUsage(..)
    , CertificateRejectReason(..)
    , defaultParamsClient
    , defaultParamsServer
    , defaultLogging

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
    , CompressionC(..)
    , Compression(..)
    , nullCompression
    -- * Ciphers & Predefined ciphers
    , Cipher(..)
    , Bulk(..)
    -- * Versions
    , Version(..)
    -- * Errors
    , TLSError(..)
    -- * Exceptions
    , HandshakeFailed(..)
    , ConnectionNotEstablished(..)
    ) where

import Network.TLS.Struct (Version(..), TLSError(..))
import Network.TLS.Crypto (PrivateKey(..))
import Network.TLS.Cipher (Cipher(..), Bulk(..))
import Network.TLS.Compression (CompressionC(..), Compression(..), nullCompression)
import Network.TLS.Context
import Network.TLS.Core
import Network.TLS.Session
