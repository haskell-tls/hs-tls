{-# LANGUAGE CPP #-}
-- |
-- Module      : Network.TLS
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Native Haskell TLS and SSL protocol implementation for server and
-- client.
--
-- This provides a high-level implementation of a sensitive security
-- protocol, eliminating a common set of security issues through the
-- use of the advanced type system, high level constructions and
-- common Haskell features.
--
-- Currently implement the SSL3.0, TLS1.0, TLS1.1, TLS1.2 and TLS 1.3
-- protocol, and support RSA and Ephemeral (Elliptic curve and
-- regular) Diffie Hellman key exchanges, and many extensions.
--
-- Some debug tools linked with tls, are available through the
-- http://hackage.haskell.org/package/tls-debug/.

module Network.TLS
    (
    -- * Basic APIs
      Context
    , contextNew
    , handshake
    , sendData
    , recvData
    , bye

    -- * Backend abstraction
    , HasBackend(..)
    , Backend(..)

    -- * Parameters
    -- intentionally hide the internal methods even haddock warns.
    , TLSParams
    , ClientParams(..)
    , defaultParamsClient
    , ServerParams(..)
    -- ** Shared
    , Shared(..)
    -- ** Hooks
    , ClientHooks(..)
    , OnCertificateRequest
    , OnServerCertificate
    , ServerHooks(..)
    , Measurement(..)
    -- ** Supported
    , Supported(..)
    -- ** Debug parameters
    , DebugParams(..)

    -- * Shared parameters
    -- ** Credentials
    , Credentials(..)
    , Credential
    , credentialLoadX509
    , credentialLoadX509FromMemory
    , credentialLoadX509Chain
    , credentialLoadX509ChainFromMemory
    -- ** Session manager
    , SessionManager(..)
    , noSessionManager
    , SessionID
    , SessionData(..)
    , SessionFlag(..)
    , TLS13TicketInfo
    -- ** Validation Cache
    , ValidationCache(..)
    , ValidationCacheQueryCallback
    , ValidationCacheAddCallback
    , ValidationCacheResult(..)
    , exceptionValidationCache

    -- * Types
    -- ** For 'Supported'
    , Version(..)
    , Compression(..)
    , nullCompression
    , HashAndSignatureAlgorithm
    , HashAlgorithm(..)
    , SignatureAlgorithm(..)
    , Group(..)
    , EMSMode(..)
    -- ** For parameters and hooks
    , DHParams
    , DHPublic
    , GroupUsage(..)
    , CertificateUsage(..)
    , CertificateRejectReason(..)
    , CertificateType(..)
    , HostName
    , MaxFragmentEnum(..)

    -- * Advanced APIs
    -- ** Backend
    , ctxConnection
    , contextFlush
    , contextClose
    -- ** Information gathering
    , Information(..)
    , contextGetInformation
    , ClientRandom
    , ServerRandom
    , unClientRandom
    , unServerRandom
    , HandshakeMode13(..)
    , getClientCertificateChain
    -- ** Negotiated
    , getNegotiatedProtocol
    , getClientSNI
    -- ** Post-handshake actions
    , updateKey
    , KeyUpdateRequest(..)
    , requestCertificate
    -- ** Modifying hooks in context
    , Hooks(..)
    , contextModifyHooks
    , Handshake
    , contextHookSetHandshakeRecv
    , Handshake13
    , contextHookSetHandshake13Recv
    , contextHookSetCertificateRecv
    , Logging(..)
    , Header(..)
    , ProtocolType(..)
    , contextHookSetLogging

    -- * Errors and exceptions
    -- ** Errors
    , TLSError(..)
    , KxError(..)
    , AlertDescription(..)
    -- ** Exceptions
    , TLSException(..)

    -- * Raw types
    -- ** Compressions class
    , CompressionC(..)
    , CompressionID
    -- ** Crypto Key
    , PubKey(..)
    , PrivKey(..)
    -- ** Ciphers & Predefined ciphers
    , module Network.TLS.Cipher

    -- * Deprecated
    , recvData'
    , contextNewOnHandle
#ifdef INCLUDE_NETWORK
    , contextNewOnSocket
#endif
    , Bytes
    , ValidationChecks(..)
    , ValidationHooks(..)
    ) where

import Network.TLS.Backend (Backend(..), HasBackend(..))
import Network.TLS.Cipher
import Network.TLS.Compression (CompressionC(..), Compression(..), nullCompression)
import Network.TLS.Context
import Network.TLS.Core
import Network.TLS.Credentials
import Network.TLS.Crypto (KxError(..), DHParams, DHPublic, Group(..))
import Network.TLS.Handshake.State (HandshakeMode13(..))
import Network.TLS.Hooks
import Network.TLS.Measurement
import Network.TLS.Parameters
import Network.TLS.Session
import qualified Network.TLS.State as S
import Network.TLS.Struct ( TLSError(..), TLSException(..)
                          , HashAndSignatureAlgorithm, HashAlgorithm(..), SignatureAlgorithm(..)
                          , Header(..), ProtocolType(..), CertificateType(..)
                          , AlertDescription(..)
                          , ClientRandom(..), ServerRandom(..)
                          , Handshake)
import Network.TLS.Struct13 ( Handshake13 )
import Network.TLS.Types
import Network.TLS.X509

import Data.ByteString as B
import Data.X509 (PubKey(..), PrivKey(..))
import Data.X509.Validation hiding (HostName)

{-# DEPRECATED Bytes "Use Data.ByteString.Bytestring instead of Bytes." #-}
type Bytes = B.ByteString

-- | Getting certificates from a client, if any.
--   Note that the certificates are not sent by a client
--   on resumption even if client authentication is required.
--   So, this API would be replaced by the one which can treat
--   both cases of full-negotiation and resumption.
getClientCertificateChain :: Context -> IO (Maybe CertificateChain)
getClientCertificateChain ctx = usingState_ ctx S.getClientCertificateChain
