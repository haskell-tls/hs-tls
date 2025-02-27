-- |
-- Native Haskell TLS protocol implementation for servers and
-- clients.
--
-- This provides a high-level implementation of a sensitive security
-- protocol, eliminating a common set of security issues through the
-- use of the advanced type system, high level constructions and
-- common Haskell features.
--
-- Currently implement the TLS1.2 and TLS 1.3
-- protocol, and support RSA and Ephemeral (Elliptic curve and
-- regular) Diffie Hellman key exchanges, and many extensions.
--
-- The tipical usage is:
--
-- > socket <- ...
-- > ctx <- contextNew socket <params>
-- > handshake ctx
-- > ... (using recvData and sendData)
-- > bye
module Network.TLS (
    -- * Basic APIs
    Context,
    contextNew,
    handshake,
    sendData,
    recvData,
    bye,

    -- * Exceptions
    -- $exceptions

    -- * Backend abstraction
    HasBackend (..),
    Backend (..),

    -- * Parameters

    -- intentionally hide the internal methods even haddock warns.
    TLSParams,

    -- ** Client parameters
    ClientParams,
    defaultParamsClient,
    clientServerIdentification,
    clientUseServerNameIndication,
    clientWantSessionResume,
    clientWantSessionResumeList,
    clientShared,
    clientHooks,
    clientSupported,
    clientDebug,
    clientUseEarlyData,

    -- ** Server parameters
    ServerParams,
    defaultParamsServer,
    serverWantClientCert,
    serverCACertificates,
    serverDHEParams,
    serverHooks,
    serverShared,
    serverSupported,
    serverDebug,
    serverEarlyDataSize,
    serverTicketLifetime,
    serverECHKey,

    -- ** Shared
    Shared,
    defaultShared,
    sharedCredentials,
    sharedSessionManager,
    sharedCAStore,
    sharedValidationCache,
    sharedHelloExtensions,
    sharedECHConfig,
    sharedLimit,

    -- ** Client hooks
    ClientHooks,
    defaultClientHooks,
    OnCertificateRequest,
    onCertificateRequest,
    OnServerCertificate,
    onServerCertificate,
    validateClientCertificate,
    onSuggestALPN,
    onCustomFFDHEGroup,
    onServerFinished,

    -- ** Server hooks
    ServerHooks,
    defaultServerHooks,
    onClientCertificate,
    onUnverifiedClientCert,
    onCipherChoosing,
    onServerNameIndication,
    onNewHandshake,
    onALPNClientSuggest,
    onEncryptedExtensionsCreating,
    Measurement,
    nbHandshakes,
    bytesReceived,
    bytesSent,

    -- ** Supported
    Supported,
    defaultSupported,
    supportedVersions,
    supportedCiphers,
    supportedCompressions,
    supportedHashSignatures,
    supportedSecureRenegotiation,
    supportedClientInitiatedRenegotiation,
    supportedExtendedMainSecret,
    supportedSession,
    supportedFallbackScsv,
    supportedEmptyPacket,
    supportedGroups,

    -- ** Debug parameters
    DebugParams,
    defaultDebugParams,
    debugSeed,
    debugPrintSeed,
    debugVersionForced,
    debugKeyLogger,
    debugError,
    debugTraceKey,

    -- ** Limit parameters
    Limit,
    defaultLimit,
    limitHandshakeFragment,
    limitRecordSize,

    -- * Shared parameters

    -- ** Credentials
    Credentials (..),
    Credential,
    credentialLoadX509,
    credentialLoadX509FromMemory,
    credentialLoadX509Chain,
    credentialLoadX509ChainFromMemory,

    -- ** Session manager
    SessionManager,
    noSessionManager,
    sessionResume,
    sessionResumeOnlyOnce,
    sessionEstablish,
    sessionInvalidate,
    sessionUseTicket,
    SessionID,
    SessionIDorTicket,
    Ticket,

    -- ** Session data
    SessionData,
    sessionVersion,
    sessionCipher,
    sessionCompression,
    sessionClientSNI,
    sessionSecret,
    sessionGroup,
    sessionTicketInfo,
    sessionALPN,
    sessionMaxEarlyDataSize,
    sessionFlags,
    SessionFlag (..),
    TLS13TicketInfo,
    is0RTTPossible,

    -- ** Validation Cache
    ValidationCache (..),
    defaultValidationCache,
    ValidationCacheQueryCallback,
    ValidationCacheAddCallback,
    ValidationCacheResult (..),
    exceptionValidationCache,

    -- * Types

    -- ** For 'Supported'
    Version (..),
    Compression (..),
    nullCompression,
    HashAndSignatureAlgorithm,
    supportedSignatureSchemes,
    HashAlgorithm (..),
    SignatureAlgorithm (..),
    Group (..),
    supportedNamedGroups,
    EMSMode (..),

    -- ** For parameters and hooks
    DHParams,
    DHPublic,
    GroupUsage (..),
    CertificateUsage (..),
    CertificateRejectReason (..),
    CertificateType (..),
    CertificateChain (..),
    HostName,
    MaxFragmentEnum (..),

    -- * Advanced APIs

    -- ** Backend
    ctxBackend,
    contextFlush,
    contextClose,

    -- ** Information gathering
    Information,
    contextGetInformation,
    infoVersion,
    infoCipher,
    infoCompression,
    infoMainSecret,
    infoExtendedMainSecret,
    infoClientRandom,
    infoServerRandom,
    infoSupportedGroup,
    infoTLS12Resumption,
    infoTLS13HandshakeMode,
    infoIsEarlyDataAccepted,
    infoIsECHAccepted,
    ClientRandom,
    ServerRandom,
    unClientRandom,
    unServerRandom,
    HandshakeMode13 (..),
    getClientCertificateChain,

    -- ** Negotiated
    getNegotiatedProtocol,
    getClientSNI,

    -- ** Post-handshake actions
    updateKey,
    KeyUpdateRequest (..),
    requestCertificate,
    getTLSUnique,
    getTLSExporter,
    getTLSServerEndPoint,
    getFinished,
    getPeerFinished,

    -- ** Modifying hooks in context
    Hooks,
    defaultHooks,
    hookRecvHandshake,
    hookRecvHandshake13,
    hookRecvCertificates,
    hookLogging,
    contextModifyHooks,
    Handshake,
    contextHookSetHandshakeRecv,
    Handshake13,
    contextHookSetHandshake13Recv,
    contextHookSetCertificateRecv,
    Logging,
    defaultLogging,
    loggingPacketSent,
    loggingPacketRecv,
    loggingIOSent,
    loggingIORecv,
    Header (..),
    ProtocolType (..),
    contextHookSetLogging,

    -- * Errors and exceptions

    -- ** Errors
    TLSError (..),
    KxError (..),
    AlertDescription (..),

    -- ** Exceptions
    TLSException (..),

    -- * Raw types

    -- ** Compressions class
    CompressionC (..),
    CompressionID,

    -- ** Crypto Key
    PubKey (..),
    PrivKey (..),

    -- ** Ciphers & Predefined ciphers
    module Network.TLS.Cipher,

    -- * Deprecated
    recvData',
    Bytes,
    ValidationChecks (..),
    ValidationHooks (..),
    clientUseMaxFragmentLength,
) where

import Data.X509 (PrivKey (..), PubKey (..))
import Data.X509.Validation hiding (HostName, defaultHooks)

import Network.TLS.Backend (Backend (..), HasBackend (..))
import Network.TLS.Cipher
import Network.TLS.Compression (
    Compression (..),
    CompressionC (..),
    nullCompression,
 )
import Network.TLS.Context
import Network.TLS.Core
import Network.TLS.Credentials
import Network.TLS.Crypto (
    DHParams,
    DHPublic,
    Group (..),
    KxError (..),
    supportedNamedGroups,
 )
import Network.TLS.Handshake.State (HandshakeMode13 (..))
import Network.TLS.Hooks
import Network.TLS.Imports
import Network.TLS.Measurement
import Network.TLS.Parameters
import Network.TLS.Session
import qualified Network.TLS.State as S
import Network.TLS.Struct (
    AlertDescription (..),
    CertificateType (..),
    ClientRandom (..),
    Handshake,
    HashAlgorithm (..),
    HashAndSignatureAlgorithm,
    Header (..),
    ProtocolType (..),
    ServerRandom (..),
    SignatureAlgorithm (..),
    TLSError (..),
    TLSException (..),
    supportedSignatureSchemes,
 )
import Network.TLS.Struct13 (Handshake13)
import Network.TLS.Types
import Network.TLS.X509

{-# DEPRECATED Bytes "Use Data.ByteString.Bytestring instead of Bytes." #-}
type Bytes = ByteString

-- | Getting certificates from a client, if any.
--   Note that the certificates are not sent by a client
--   on resumption even if client authentication is required.
--   So, this API would be replaced by the one which can treat
--   both cases of full-negotiation and resumption.
getClientCertificateChain :: Context -> IO (Maybe CertificateChain)
getClientCertificateChain ctx = usingState_ ctx S.getClientCertificateChain

-- $exceptions
--     Since 1.8.0, this library only throws exceptions of type 'TLSException'.
--     In the common case where the chosen backend is socket, 'IOException'
--     may be thrown as well. This happens because the backend for sockets,
--     opaque to most modules in the @tls@ library, throws those exceptions.
