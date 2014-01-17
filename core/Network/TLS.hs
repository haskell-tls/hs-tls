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
    , noSessionManager
    , setSessionManager

    -- * Backend abstraction
    , Backend(..)

    -- * Context object
    , Context
    , ctxConnection

    -- * Creating a context
    , contextNew
    , contextNewOnHandle
    , contextNewOnSocket
    , contextFlush
    , contextClose
    , contextHookSetHandshakeRecv

    -- * Information gathering
    , Information(..)
    , contextGetInformation

    -- * Credentials
    , Credentials(..)
    , Credential
    , credentialLoadX509

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
    , PubKey(..)
    , PrivKey(..)

    -- * Compressions & Predefined compressions
    , module Network.TLS.Compression

    -- * Ciphers & Predefined ciphers
    , module Network.TLS.Cipher

    -- * Versions
    , Version(..)

    -- * Errors
    , TLSError(..)
    , KxError(..)
    , AlertDescription(..)

    -- * Exceptions
    , TLSException(..)
    ) where

import Network.TLS.Backend (Backend(..))
import Network.TLS.Struct ( Version(..), TLSError(..), TLSException(..)
                          , HashAndSignatureAlgorithm, HashAlgorithm(..), SignatureAlgorithm(..)
                          , Header(..), ProtocolType(..), CertificateType(..)
                          , AlertDescription(..))
import Network.TLS.Crypto (KxError(..))
import Network.TLS.Cipher
import Network.TLS.Credentials
import Network.TLS.Compression (CompressionC(..), Compression(..), nullCompression)
import Network.TLS.Context
import Network.TLS.Core
import Network.TLS.Session
import Data.X509 (PubKey(..), PrivKey(..))
