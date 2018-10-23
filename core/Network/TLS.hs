{-# LANGUAGE CPP #-}
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
      ClientParams(..)
    , HostName
    , Bytes
    , ServerParams(..)
    , DebugParams(..)
    , DHParams
    , DHPublic
    , ClientHooks(..)
    , ServerHooks(..)
    , Supported(..)
    , Shared(..)
    , Hooks(..)
    , Handshake
    , Logging(..)
    , Measurement(..)
    , GroupUsage(..)
    , CertificateUsage(..)
    , CertificateRejectReason(..)
    , defaultParamsClient
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
    , TLS13TicketInfo

    -- * Backend abstraction
    , Backend(..)

    -- * Context object
    , Context
    , ctxConnection
    , TLSParams
    , HasBackend(..)

    -- * Creating a context
    , contextNew
    , contextNewOnHandle
#ifdef INCLUDE_NETWORK
    , contextNewOnSocket
#endif
    , contextFlush
    , contextClose
    , contextHookSetHandshakeRecv
    , contextHookSetCertificateRecv
    , contextHookSetLogging
    , contextModifyHooks

    -- * Information gathering
    , Information(..)
    , ClientRandom
    , ServerRandom

    , unClientRandom
    , unServerRandom
    , contextGetInformation

    -- * Credentials
    , Credentials(..)
    , Credential
    , credentialLoadX509
    , credentialLoadX509FromMemory
    , credentialLoadX509Chain
    , credentialLoadX509ChainFromMemory

    -- * Initialisation and Termination of context
    , bye
    , handshake

    -- * Application Layer Protocol Negotiation
    , getNegotiatedProtocol

    -- * Server Name Indication
    , getClientSNI

    -- * High level API
    , sendData
    , recvData
    , recvData'
    , updateKey

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

    -- * X509 Validation
    , ValidationChecks(..)
    , ValidationHooks(..)

    -- * X509 Validation Cache
    , ValidationCache(..)
    , ValidationCacheResult(..)
    , exceptionValidationCache

    -- * TLS 1.3
    , Group(..)
    , HandshakeMode13(..)
    ) where

import Network.TLS.Backend (Backend(..), HasBackend(..))
import Network.TLS.Struct ( TLSError(..), TLSException(..)
                          , HashAndSignatureAlgorithm, HashAlgorithm(..), SignatureAlgorithm(..)
                          , Header(..), ProtocolType(..), CertificateType(..)
                          , AlertDescription(..)
                          , ClientRandom(..), ServerRandom(..)
                          , Handshake)
import Network.TLS.Crypto (KxError(..), DHParams, DHPublic, Group(..))
import Network.TLS.Cipher
import Network.TLS.Hooks
import Network.TLS.Measurement
import Network.TLS.Credentials
import Network.TLS.Compression (CompressionC(..), Compression(..), nullCompression)
import Network.TLS.Context
import Network.TLS.Parameters
import Network.TLS.Core
import Network.TLS.Session
import Network.TLS.X509
import Network.TLS.Types
import Network.TLS.Handshake.State (HandshakeMode13(..))
import Data.X509 (PubKey(..), PrivKey(..))
import Data.X509.Validation
import Data.ByteString as B

{-# DEPRECATED Bytes "Use Data.ByteString.Bytestring instead of Bytes." #-}
type Bytes = B.ByteString
