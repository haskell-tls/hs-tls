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
    -- ** Supported
    , Supported(..)
    -- ** Debug parameters
    , DebugParams(..)
    -- ** Types
    , HostName
    , DHParams
    , DHPublic
    , Measurement(..)
    , GroupUsage(..)
    , CertificateUsage(..)
    , CertificateRejectReason(..)
    , MaxFragmentEnum(..)
    , HashAndSignatureAlgorithm
    , HashAlgorithm(..)
    , SignatureAlgorithm(..)
    , CertificateType(..)

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
    , TLS13TicketInfo
    -- ** Validation Cache
    , ValidationCache(..)
    , ValidationCacheQueryCallback
    , ValidationCacheAddCallback
    , ValidationCacheResult(..)
    , exceptionValidationCache

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
    -- ** Negotiated
    , getNegotiatedProtocol
    , getClientSNI
    -- ** Post-handshake actions
    , updateKey
    , KeyUpdateRequest(..)
    , requestCertificate
    -- ** Modifying context
    , Hooks(..)
    , contextModifyHooks
    , Handshake
    , contextHookSetHandshakeRecv
    , Handshake13
    , contextHookSetHandshake13Recv
    , contextHookSetCertificateRecv
    , Logging(..)
    , contextHookSetLogging

    -- * Raw types
    , ProtocolType(..)
    , Header(..)
    , Version(..)
    -- ** Compressions & Predefined compressions
    , module Network.TLS.Compression
    , CompressionID
    -- ** Ciphers & Predefined ciphers
    , module Network.TLS.Cipher
    -- ** Crypto Key
    , PubKey(..)
    , PrivKey(..)
    -- ** TLS 1.3
    , Group(..)
    , HandshakeMode13(..)

    -- * Errors and exceptions
    -- ** Errors
    , TLSError(..)
    , KxError(..)
    , AlertDescription(..)

    -- ** Exceptions
    , TLSException(..)

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
