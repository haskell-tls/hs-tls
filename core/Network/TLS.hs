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
    , ServerParams(..)
    , DebugParams(..)
    , ClientHooks(..)
    , ServerHooks(..)
    , Supported(..)
    , Shared(..)
    , Hooks(..)
    , Logging(..)
    , Measurement(..)
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

    -- * Backend abstraction
    , Backend(..)

    -- * Context object
    , Context
    , ctxConnection
    , TLSParams
    , HasBackend

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

    -- * Next Protocol Negotiation
    , getNegotiatedProtocol

    -- * Server Name Indication
    , getClientSNI

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

    -- * X509 Validation
    , ValidationChecks(..)
    , ValidationHooks(..)

    -- * X509 Validation Cache
    , ValidationCache(..)
    , ValidationCacheResult(..)
    , exceptionValidationCache
    ) where

import Network.TLS.Backend (Backend(..), HasBackend)
import Network.TLS.Struct ( TLSError(..), TLSException(..)
                          , HashAndSignatureAlgorithm, HashAlgorithm(..), SignatureAlgorithm(..)
                          , Header(..), ProtocolType(..), CertificateType(..)
                          , AlertDescription(..)
                          , ClientRandom(..), ServerRandom(..))
import Network.TLS.Crypto (KxError(..))
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
import Data.X509 (PubKey(..), PrivKey(..))
import Data.X509.Validation
