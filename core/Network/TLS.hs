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
      contextNew
    , handshake
    , sendData
    , recvData
    , bye

    -- * Backend abstraction
    , HasBackend(..)
    , Backend(..)

    -- * Context configuration
    -- ** Parameters
    , TLSParams
    , ClientParams(..)
    , defaultParamsClient
    , ServerParams(..)
    -- ** Hooks
    , ClientHooks(..)
    , ServerHooks(..)
    -- ** Supported
    , Supported(..)
    -- ** Shared
    , Shared(..)
    -- ** Credentials
    , Credentials(..)
    , Credential
    , credentialLoadX509
    , credentialLoadX509FromMemory
    , credentialLoadX509Chain
    , credentialLoadX509ChainFromMemory
    -- ** Session
    , SessionID
    , SessionData(..)
    , SessionManager(..)
    , noSessionManager
    , TLS13TicketInfo
    -- ** Misc
    , DebugParams(..)
    , HostName
    , DHParams
    , DHPublic
    , Hooks(..)
    , Handshake
    , Logging(..)
    , Measurement(..)
    , GroupUsage(..)
    , CertificateUsage(..)
    , CertificateRejectReason(..)
    , MaxFragmentEnum(..)
    , HashAndSignatureAlgorithm
    , HashAlgorithm(..)
    , SignatureAlgorithm(..)
    , CertificateType(..)

    -- * X509
    -- ** X509 Validation
    , ValidationChecks(..)
    , ValidationHooks(..)

    -- ** X509 Validation Cache
    , ValidationCache(..)
    , ValidationCacheResult(..)
    , exceptionValidationCache

    -- * Context
    , Context
    , ctxConnection
    , contextFlush
    , contextClose
    , contextHookSetHandshakeRecv
    , contextHookSetCertificateRecv
    , contextHookSetLogging
    , contextModifyHooks

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
    -- ** Updating keys
    , updateKey
    , KeyUpdateRequest(..)

    -- * Raw types
    , ProtocolType(..)
    , Header(..)
    , Version(..)
    -- ** Compressions & Predefined compressions
    , module Network.TLS.Compression
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
