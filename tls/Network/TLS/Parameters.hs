module Network.TLS.Parameters (
    ClientParams (..),
    defaultParamsClient,
    ServerParams (..),
    defaultParamsServer,
    CommonParams,
    DebugParams (..),
    defaultDebugParams,
    ClientHooks (..),
    defaultClientHooks,
    OnCertificateRequest,
    OnServerCertificate,
    ServerHooks (..),
    defaultServerHooks,
    Supported (..),
    defaultSupported,
    Shared (..),
    defaultShared,
    Limit (..),
    defaultLimit,

    -- * Parameters
    MaxFragmentEnum (..),
    EMSMode (..),
    GroupUsage (..),
    CertificateUsage (..),
    CertificateRejectReason (..),
    Information (..),
) where

import Crypto.HPKE
import Data.Default (Default (def))

import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Credentials
import Network.TLS.Crypto
import Network.TLS.ECH.Config
import Network.TLS.Extension
import Network.TLS.Extra.Cipher
import Network.TLS.Handshake.State
import Network.TLS.Imports
import Network.TLS.Measurement
import Network.TLS.RNG (Seed)
import Network.TLS.Session
import Network.TLS.Struct
import qualified Network.TLS.Struct as Struct
import Network.TLS.Types (HostName)
import Network.TLS.X509

type CommonParams = (Supported, Shared, DebugParams)

-- | All settings should not be used in production
data DebugParams = DebugParams
    { debugSeed :: Maybe Seed
    -- ^ Disable the true randomness in favor of deterministic seed that will produce
    -- a deterministic random from. This is useful for tests and debugging purpose.
    -- Do not use in production
    --
    -- Default: 'Nothing'
    , debugPrintSeed :: Seed -> IO ()
    -- ^ Add a way to print the seed that was randomly generated. re-using the same seed
    -- will reproduce the same randomness with 'debugSeed'
    --
    -- Default: no printing
    , debugVersionForced :: Maybe Version
    -- ^ Force to choose this version in the server side.
    --
    -- Default: 'Nothing'
    , debugKeyLogger :: String -> IO ()
    -- ^ Printing main keys.
    --
    -- Default: no printing
    }

-- | Default value for 'DebugParams'
defaultDebugParams :: DebugParams
defaultDebugParams =
    DebugParams
        { debugSeed = Nothing
        , debugPrintSeed = const (return ())
        , debugVersionForced = Nothing
        , debugKeyLogger = \_ -> return ()
        }

instance Show DebugParams where
    show _ = "DebugParams"
instance Default DebugParams where
    def = defaultDebugParams

{-# DEPRECATED clientUseMaxFragmentLength "UseMaxFragmentLength is deprecated" #-}

data ClientParams = ClientParams
    { clientUseMaxFragmentLength :: Maybe MaxFragmentEnum
    -- ^
    --
    -- Default: 'Nothing'
    , clientServerIdentification :: (HostName, ByteString)
    -- ^ Define the name of the server, along with an extra service identification blob.
    -- this is important that the hostname part is properly filled for security reason,
    -- as it allow to properly associate the remote side with the given certificate
    -- during a handshake.
    --
    -- The extra blob is useful to differentiate services running on the same host, but that
    -- might have different certificates given. It's only used as part of the X509 validation
    -- infrastructure.
    --
    -- This value is typically set by 'defaultParamsClient'.
    , clientUseServerNameIndication :: Bool
    -- ^ Allow the use of the Server Name Indication TLS extension during handshake, which allow
    -- the client to specify which host name, it's trying to access. This is useful to distinguish
    -- CNAME aliasing (e.g. web virtual host).
    --
    -- Default: 'True'
    , clientWantSessionResume :: Maybe (SessionID, SessionData)
    -- ^ try to establish a connection using this session for TLS 1.2/TLS 1.3.
    -- This can be used for TLS 1.3 but for backward compatibility purpose only.
    -- Use 'clientWantSessionResume13' instead for TLS 1.3.
    --
    -- Default: 'Nothing'
    , clientWantSessionResumeList :: [(SessionID, SessionData)]
    -- ^ try to establish a connection using one of this sessions
    -- especially for TLS 1.3.
    -- This take precedence over 'clientWantSessionResume'.
    -- For convenience, this can be specified for TLS 1.2 but only the first
    -- entry is used.
    --
    -- Default: '[]'
    , clientShared :: Shared
    -- ^ See the default value of 'Shared'.
    , clientHooks :: ClientHooks
    -- ^ See the default value of 'ClientHooks'.
    , clientSupported :: Supported
    -- ^ In this element, you'll  need to override the default empty value of
    -- of 'supportedCiphers' with a suitable cipherlist.
    --
    -- See the default value of 'Supported'.
    , clientDebug :: DebugParams
    -- ^ See the default value of 'DebugParams'.
    , clientUseEarlyData :: Bool
    -- ^ Client tries to send early data in TLS 1.3
    -- via 'sendData' if possible.
    -- If not accepted by the server, the early data
    -- is automatically re-sent.
    --
    -- Default: 'False'
    }
    deriving (Show)

-- | Default value for 'ClientParams'
defaultParamsClient :: HostName -> ByteString -> ClientParams
defaultParamsClient serverName serverId =
    ClientParams
        { clientUseMaxFragmentLength = Nothing
        , clientServerIdentification = (serverName, serverId)
        , clientUseServerNameIndication = True
        , clientWantSessionResume = Nothing
        , clientWantSessionResumeList = []
        , clientShared = def
        , clientHooks = def
        , clientSupported = def
        , clientDebug = defaultDebugParams
        , clientUseEarlyData = False
        }

data ServerParams = ServerParams
    { serverWantClientCert :: Bool
    -- ^ Request a certificate from client.
    --
    -- Default: 'False'
    , serverCACertificates :: [SignedCertificate]
    -- ^ This is a list of certificates from which the
    -- disinguished names are sent in certificate request
    -- messages.  For TLS1.0, it should not be empty.
    --
    -- Default: '[]'
    , serverDHEParams :: Maybe DHParams
    -- ^ Server Optional Diffie Hellman parameters.  Setting parameters is
    -- necessary for FFDHE key exchange when clients are not compatible
    -- with RFC 7919.
    --
    -- Value can be one of the standardized groups from module
    -- "Network.TLS.Extra.FFDHE" or custom parameters generated with
    -- 'Crypto.PubKey.DH.generateParams'.
    --
    -- Default: 'Nothing'
    , serverHooks :: ServerHooks
    -- ^ See the default value of 'ServerHooks'.
    , serverShared :: Shared
    -- ^ See the default value of 'Shared'.
    , serverSupported :: Supported
    -- ^ See the default value of 'Supported'.
    , serverDebug :: DebugParams
    -- ^ See the default value of 'DebugParams'.
    , serverEarlyDataSize :: Int
    -- ^ Server accepts this size of early data in TLS 1.3.
    -- 0 (or lower) means that the server does not accept early data.
    --
    -- Default: 0
    , serverTicketLifetime :: Int
    -- ^ Lifetime in seconds for session tickets generated by the server.
    -- Acceptable value range is 0 to 604800 (7 days).
    --
    -- Default: 7200 (2 hours)
    , serverECHKey :: [(ConfigId, ByteString)]
    -- ^ ECH secret keys.
    --
    -- @since 2.1.8
    }
    deriving (Show)

defaultParamsServer :: ServerParams
defaultParamsServer =
    ServerParams
        { serverWantClientCert = False
        , serverCACertificates = []
        , serverDHEParams = Nothing
        , serverHooks = def
        , serverShared = def
        , serverSupported = def
        , serverDebug = defaultDebugParams
        , serverEarlyDataSize = 0
        , serverTicketLifetime = 7200
        , serverECHKey = []
        }

instance Default ServerParams where
    def = defaultParamsServer

-- | List all the supported algorithms, versions, ciphers, etc supported.
data Supported = Supported
    { supportedVersions :: [Version]
    -- ^ Supported versions by this context.  On the client side, the highest
    -- version will be used to establish the connection.  On the server side,
    -- the highest version that is less or equal than the client version will
    -- be chosen.
    --
    -- Versions should be listed in preference order, i.e. higher versions
    -- first.
    --
    -- Default: @[TLS13,TLS12]@
    , supportedCiphers :: [Cipher]
    -- ^ Supported cipher methods.  The default is empty, specify a suitable
    -- cipher list.  'Network.TLS.Extra.Cipher.ciphersuite_default' is often
    -- a good choice.
    --
    -- Default: @[]@
    , supportedCompressions :: [Compression]
    -- ^ Supported compressions methods.  By default only the "null"
    -- compression is supported, which means no compression will be performed.
    -- Allowing other compression method is not advised as it causes a
    -- connection failure when TLS 1.3 is negotiated.
    --
    -- Default: @[nullCompression]@
    , supportedHashSignatures :: [HashAndSignatureAlgorithm]
    -- ^ All supported hash/signature algorithms pair for client
    -- certificate verification and server signature in (EC)DHE,
    -- ordered by decreasing priority.
    --
    -- This list is sent to the peer as part of the "signature_algorithms"
    -- extension.  It is used to restrict accepted signatures received from
    -- the peer at TLS level (not in X.509 certificates), but only when the
    -- TLS version is 1.2 or above.  In order to disable SHA-1 one must then
    -- also disable earlier protocol versions in 'supportedVersions'.
    --
    -- The list also impacts the selection of possible algorithms when
    -- generating signatures.
    --
    -- Note: with TLS 1.3 some algorithms have been deprecated and will not be
    -- used even when listed in the parameter: MD5, SHA-1, SHA-224, RSA
    -- PKCS#1, DSA.
    --
    -- Default:
    --
    -- @
    --   [ (HashIntrinsic,     SignatureEd448)
    --   , (HashIntrinsic,     SignatureEd25519)
    --   , (Struct.HashSHA256, SignatureECDSA)
    --   , (Struct.HashSHA384, SignatureECDSA)
    --   , (Struct.HashSHA512, SignatureECDSA)
    --   , (HashIntrinsic,     SignatureRSApssRSAeSHA512)
    --   , (HashIntrinsic,     SignatureRSApssRSAeSHA384)
    --   , (HashIntrinsic,     SignatureRSApssRSAeSHA256)
    --   , (Struct.HashSHA512, SignatureRSA)
    --   , (Struct.HashSHA384, SignatureRSA)
    --   , (Struct.HashSHA256, SignatureRSA)
    --   , (Struct.HashSHA1,   SignatureRSA)
    --   , (Struct.HashSHA1,   SignatureDSA)
    --   ]
    -- @
    , supportedSecureRenegotiation :: Bool
    -- ^ Secure renegotiation defined in RFC5746.
    --   If 'True', clients send the renegotiation_info extension.
    --   If 'True', servers handle the extension or the renegotiation SCSV
    --   then send the renegotiation_info extension.
    --
    --   Default: 'True'
    , supportedClientInitiatedRenegotiation :: Bool
    -- ^ If 'True', renegotiation is allowed from the client side.
    --   This is vulnerable to DOS attacks.
    --   If 'False', renegotiation is allowed only from the server side
    --   via HelloRequest.
    --
    --   Default: 'False'
    , supportedExtendedMainSecret :: EMSMode
    -- ^ The mode regarding extended main secret.  Enabling this extension
    -- provides better security for TLS versions 1.2.  TLS 1.3 provides
    -- the security properties natively and does not need the extension.
    --
    -- By default the extension is 'RequireEMS'.
    -- So, the handshake will fail when the peer does not support
    -- the extension.
    --
    -- Default: 'RequireEMS'
    , supportedSession :: Bool
    -- ^ Set if we support session.
    --
    --   Default: 'True'
    , supportedFallbackScsv :: Bool
    -- ^ Support for fallback SCSV defined in RFC7507.
    --   If 'True', servers reject handshakes which suggest
    --   a lower protocol than the highest protocol supported.
    --
    --   Default: 'True'
    , supportedEmptyPacket :: Bool
    -- ^ In ver <= TLS1.0, block ciphers using CBC are using CBC residue as IV, which can be guessed
    -- by an attacker. Hence, an empty packet is normally sent before a normal data packet, to
    -- prevent guessability. Some Microsoft TLS-based protocol implementations, however,
    -- consider these empty packets as a protocol violation and disconnect. If this parameter is
    -- 'False', empty packets will never be added, which is less secure, but might help in rare
    -- cases.
    --
    --   Default: 'True'
    , supportedGroups :: [Group]
    -- ^ A list of supported elliptic curves and finite-field groups in the
    --   preferred order.
    --
    --   The list is sent to the server as part of the "supported_groups"
    --   extension.  It is used in both clients and servers to restrict
    --   accepted groups in DH key exchange.  Up until TLS v1.2, it is also
    --   used by a client to restrict accepted elliptic curves in ECDSA
    --   signatures.
    --
    --   The default value includes all groups with security strength of 128
    --   bits or more.
    --
    --   Default: @[X25519,X448,P256,FFDHE2048,FFDHE3072,FFDHE4096,P384,FFDHE6144,FFDHE8192,P521]@
    , supportedHPKE :: [(KEM_ID, KDF_ID, AEAD_ID)]
    -- ^ Client only.
    --
    -- @since 2.1.8
    }
    deriving (Show, Eq)

-- | Client or server policy regarding Extended Main Secret
data EMSMode
    = -- | Extended Main Secret is not used
      NoEMS
    | -- | Extended Main Secret is allowed
      AllowEMS
    | -- | Extended Main Secret is required
      RequireEMS
    deriving (Show, Eq)

defaultHPKE :: [(KEM_ID, KDF_ID, AEAD_ID)]
defaultHPKE =
    [ (DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, AES_128_GCM)
    , (DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, ChaCha20Poly1305)
    , (DHKEM_P256_HKDF_SHA256, HKDF_SHA256, AES_128_GCM)
    , (DHKEM_P256_HKDF_SHA256, HKDF_SHA512, AES_128_GCM)
    , (DHKEM_P256_HKDF_SHA256, HKDF_SHA256, ChaCha20Poly1305)
    , (DHKEM_P521_HKDF_SHA512, HKDF_SHA512, AES_256_GCM)
    ]

defaultSupported :: Supported
defaultSupported =
    Supported
        { supportedVersions = [TLS13, TLS12]
        , supportedCiphers = ciphersuite_default
        , supportedCompressions = [nullCompression]
        , supportedHashSignatures = Struct.supportedSignatureSchemes
        , supportedSecureRenegotiation = True
        , supportedClientInitiatedRenegotiation = False
        , supportedExtendedMainSecret = RequireEMS
        , supportedSession = True
        , supportedFallbackScsv = True
        , supportedEmptyPacket = True
        , supportedGroups = supportedNamedGroups
        , supportedHPKE = defaultHPKE
        }

instance Default Supported where
    def = defaultSupported

-- | Parameters that are common to clients and servers.
data Shared = Shared
    { sharedCredentials :: Credentials
    -- ^ The list of certificates and private keys that a server will use as
    -- part of authentication to clients.  Actual credentials that are used
    -- are selected dynamically from this list based on client capabilities.
    -- Additional credentials returned by 'onServerNameIndication' are also
    -- considered.
    --
    -- When credential list is left empty (the default value), no key
    -- exchange can take place.
    --
    -- Default: 'mempty'
    , sharedSessionManager :: SessionManager
    -- ^ Callbacks used by clients and servers in order to resume TLS
    -- sessions.  The default implementation never resumes sessions.  Package
    -- <https://hackage.haskell.org/package/tls-session-manager tls-session-manager>
    -- provides an in-memory implementation.
    --
    -- Default: 'noSessionManager'
    , sharedCAStore :: CertificateStore
    -- ^ A collection of trust anchors to be used by a client as
    -- part of validation of server certificates.  This is set as
    -- first argument to function 'onServerCertificate'.  Package
    -- <https://hackage.haskell.org/package/crypton-x509-system crypton-x509-system>
    -- gives access to a default certificate store configured in the
    -- system.
    --
    -- Default: 'mempty'
    , sharedValidationCache :: ValidationCache
    -- ^ Callbacks that may be used by a client to cache certificate
    -- validation results (positive or negative) and avoid expensive
    -- signature check.  The default implementation does not have
    -- any caching.
    --
    -- See the default value of 'ValidationCache'.
    , sharedHelloExtensions :: [ExtensionRaw]
    -- ^ Additional extensions to be sent during the Hello sequence.
    --
    -- For a client this is always included in message ClientHello.  For a
    -- server, this is sent in messages ServerHello or EncryptedExtensions
    -- based on the TLS version.
    --
    -- Default: @[]@
    , sharedECHConfig :: ECHConfigList
    -- ^ ECH configuration.
    --
    -- @since 2.1.8
    , sharedLimit :: Limit
    -- ^ Limitation parameters.
    --
    -- @since 2.1.8
    }

instance Show Shared where
    show _ = "Shared"
instance Default Shared where
    def = defaultShared

defaultShared :: Shared
defaultShared =
    Shared
        { sharedCredentials = mempty
        , sharedSessionManager = noSessionManager
        , sharedCAStore = mempty
        , sharedValidationCache = def
        , sharedHelloExtensions = []
        , sharedECHConfig = []
        , sharedLimit = defaultLimit
        }

-- | Group usage callback possible return values.
data GroupUsage
    = -- | usage of group accepted
      GroupUsageValid
    | -- | usage of group provides insufficient security
      GroupUsageInsecure
    | -- | usage of group rejected for other reason (specified as string)
      GroupUsageUnsupported String
    | -- | usage of group with an invalid public value
      GroupUsageInvalidPublic
    deriving (Show, Eq)

defaultGroupUsage :: Int -> DHParams -> DHPublic -> IO GroupUsage
defaultGroupUsage minBits params public
    | even $ dhParamsGetP params =
        return $ GroupUsageUnsupported "invalid odd prime"
    | not $ dhValid params (dhParamsGetG params) =
        return $ GroupUsageUnsupported "invalid generator"
    | not $ dhValid params (dhUnwrapPublic public) =
        return GroupUsageInvalidPublic
    -- To prevent Logjam attack
    | dhParamsGetBits params < minBits = return GroupUsageInsecure
    | otherwise = return GroupUsageValid

-- | Type for 'onCertificateRequest'. This type synonym is to make
--   document readable.
type OnCertificateRequest =
    ( [CertificateType]
    , Maybe [HashAndSignatureAlgorithm]
    , [DistinguishedName]
    )
    -> IO (Maybe (CertificateChain, PrivKey))

-- | Type for 'onServerCertificate'. This type synonym is to make
--   document readable.
type OnServerCertificate =
    CertificateStore
    -> ValidationCache
    -> ServiceID
    -> CertificateChain
    -> IO [FailedReason]

-- | A set of callbacks run by the clients for various corners of TLS establishment
data ClientHooks = ClientHooks
    { onCertificateRequest :: OnCertificateRequest
    -- ^ This action is called when the a certificate request is
    -- received from the server. The callback argument is the
    -- information from the request.  The server, at its
    -- discretion, may be willing to continue the handshake
    -- without a client certificate.  Therefore, the callback is
    -- free to return 'Nothing' to indicate that no client
    -- certificate should be sent, despite the server's request.
    -- In some cases it may be appropriate to get user consent
    -- before sending the certificate; the content of the user's
    -- certificate may be sensitive and intended only for
    -- specific servers.
    --
    -- The action should select a certificate chain of one of
    -- the given certificate types and one of the certificates
    -- in the chain should (if possible) be signed by one of the
    -- given distinguished names.  Some servers, that don't have
    -- a narrow set of preferred issuer CAs, will send an empty
    -- 'DistinguishedName' list, rather than send all the names
    -- from their trusted CA bundle.  If the client does not
    -- have a certificate chaining to a matching CA, it may
    -- choose a default certificate instead.
    --
    -- Each certificate except the last should be signed by the
    -- following one.  The returned private key must be for the
    -- first certificates in the chain.  This key will be used
    -- to signing the certificate verify message.
    --
    -- The public key in the first certificate, and the matching
    -- returned private key must be compatible with one of the
    -- list of 'HashAndSignatureAlgorithm' value when provided.
    -- TLS 1.3 changes the meaning of the list elements, adding
    -- explicit code points for each supported pair of hash and
    -- signature (public key) algorithms, rather than combining
    -- separate codes for the hash and key.  For details see
    -- <https://tools.ietf.org/html/rfc8446#section-4.2.3 RFC 8446>
    -- section 4.2.3.  When no compatible certificate chain is
    -- available, return 'Nothing' if it is OK to continue
    -- without a client certificate.  Returning a non-matching
    -- certificate should result in a handshake failure.
    --
    -- While the TLS version is not provided to the callback,
    -- the content of the @signature_algorithms@ list provides
    -- a strong hint, since TLS 1.3 servers will generally list
    -- RSA pairs with a hash component of 'Intrinsic' (@0x08@).
    --
    -- Note that is is the responsibility of this action to
    -- select a certificate matching one of the requested
    -- certificate types (public key algorithms).  Returning
    -- a non-matching one will lead to handshake failure later.
    --
    -- Default: returns 'Nothing' anyway.
    , onServerCertificate :: OnServerCertificate
    -- ^ Used by the client to validate the server certificate.  The default
    -- implementation calls 'validateDefault' which validates according to the
    -- default hooks and checks provided by "Data.X509.Validation".  This can
    -- be replaced with a custom validation function using different settings.
    --
    -- The function is not expected to verify the key-usage extension of the
    -- end-entity certificate, as this depends on the dynamically-selected
    -- cipher and this part should not be cached.  Key-usage verification
    -- is performed by the library internally.
    --
    -- Default: 'validateDefault'
    , onSuggestALPN :: IO (Maybe [ByteString])
    -- ^ This action is called when the client sends ClientHello
    --   to determine ALPN values such as '["h2", "http/1.1"]'.
    --
    -- Default: returns 'Nothing'
    , onCustomFFDHEGroup :: DHParams -> DHPublic -> IO GroupUsage
    -- ^ This action is called to validate DHE parameters when the server
    --   selected a finite-field group not part of the "Supported Groups
    --   Registry" or not part of 'supportedGroups' list.
    --
    --   With TLS 1.3 custom groups have been removed from the protocol, so
    --   this callback is only used when the version negotiated is 1.2 or
    --   below.
    --
    --   The default behavior with (dh_p, dh_g, dh_size) and pub as follows:
    --
    --   (1) rejecting if dh_p is even
    --   (2) rejecting unless 1 < dh_g && dh_g < dh_p - 1
    --   (3) rejecting unless 1 < dh_p && pub < dh_p - 1
    --   (4) rejecting if dh_size < 1024 (to prevent Logjam attack)
    --
    --   See RFC 7919 section 3.1 for recommandations.
    , onServerFinished :: Information -> IO ()
    -- ^ When a handshake is done, this hook can check `Information`.
    }

defaultClientHooks :: ClientHooks
defaultClientHooks =
    ClientHooks
        { onCertificateRequest = \_ -> return Nothing
        , onServerCertificate = validateDefault
        , onSuggestALPN = return Nothing
        , onCustomFFDHEGroup = defaultGroupUsage 1024
        , onServerFinished = \_ -> return ()
        }

instance Show ClientHooks where
    show _ = "ClientHooks"
instance Default ClientHooks where
    def = defaultClientHooks

-- | A set of callbacks run by the server for various corners of the TLS establishment
data ServerHooks = ServerHooks
    { onClientCertificate :: CertificateChain -> IO CertificateUsage
    -- ^ This action is called when a client certificate chain
    -- is received from the client.  When it returns a
    -- CertificateUsageReject value, the handshake is aborted.
    --
    -- The function is not expected to verify the key-usage
    -- extension of the certificate.  This verification is
    -- performed by the library internally.
    --
    -- Default: returns the followings:
    --
    -- @
    -- CertificateUsageReject (CertificateRejectOther "no client certificates expected")
    -- @
    , onUnverifiedClientCert :: IO Bool
    -- ^ This action is called when the client certificate
    -- cannot be verified. Return 'True' to accept the certificate
    -- anyway, or 'False' to fail verification.
    --
    -- Default: returns 'False'
    , onCipherChoosing :: Version -> [Cipher] -> Cipher
    -- ^ Allow the server to choose the cipher relative to the
    -- the client version and the client list of ciphers.
    --
    -- This could be useful with old clients and as a workaround
    -- to the BEAST (where RC4 is sometimes prefered with TLS < 1.1)
    --
    -- The client cipher list cannot be empty.
    --
    -- Default: taking the head of ciphers.
    , onServerNameIndication :: Maybe HostName -> IO Credentials
    -- ^ Allow the server to indicate additional credentials
    -- to be used depending on the host name indicated by the
    -- client.
    --
    -- This is most useful for transparent proxies where
    -- credentials must be generated on the fly according to
    -- the host the client is trying to connect to.
    --
    -- Returned credentials may be ignored if a client does not support
    -- the signature algorithms used in the certificate chain.
    --
    -- Default: returns 'mempty'
    , onNewHandshake :: Measurement -> IO Bool
    -- ^ At each new handshake, we call this hook to see if we allow handshake to happens.
    --
    -- Default: returns 'True'
    , onALPNClientSuggest :: Maybe ([ByteString] -> IO ByteString)
    -- ^ Allow the server to choose an application layer protocol
    --   suggested from the client through the ALPN
    --   (Application Layer Protocol Negotiation) extensions.
    --   If the server supports no protocols that the client advertises
    --   an empty 'ByteString' should be returned.
    --
    -- Default: 'Nothing'
    , onEncryptedExtensionsCreating :: [ExtensionRaw] -> IO [ExtensionRaw]
    -- ^ Allow to modify extensions to be sent in EncryptedExtensions
    --  of TLS 1.3.
    --
    -- Default: 'return'
    }

-- | Default value for 'ServerHooks'
defaultServerHooks :: ServerHooks
defaultServerHooks =
    ServerHooks
        { onClientCertificate = \_ ->
            return $
                CertificateUsageReject $
                    CertificateRejectOther "no client certificates expected"
        , onUnverifiedClientCert = return False
        , onCipherChoosing = \_ ccs -> case ccs of
            [] -> error "onCipherChoosing"
            c : _ -> c
        , onServerNameIndication = \_ -> return mempty
        , onNewHandshake = \_ -> return True
        , onALPNClientSuggest = Nothing
        , onEncryptedExtensionsCreating = return
        }

instance Show ServerHooks where
    show _ = "ServerHooks"
instance Default ServerHooks where
    def = defaultServerHooks

-- | Information related to a running context, e.g. current cipher
data Information = Information
    { infoVersion :: Version
    , infoCipher :: Cipher
    , infoCompression :: Compression
    , infoMainSecret :: Maybe ByteString
    , infoExtendedMainSecret :: Bool
    , infoClientRandom :: Maybe ClientRandom
    , infoServerRandom :: Maybe ServerRandom
    , infoSupportedGroup :: Maybe Group
    , infoTLS12Resumption :: Bool
    , infoTLS13HandshakeMode :: Maybe HandshakeMode13
    , infoIsEarlyDataAccepted :: Bool
    }
    deriving (Show, Eq)

-- | Limitations for security.
--
-- @since 2.1.7
data Limit = Limit
    { limitRecordSize :: Maybe Int
    -- ^ Record size limit defined in RFC 8449.
    --
    -- If 'Nothing', the "record_size_limit" extension is not used.
    --
    -- In the case of 'Just': A client sends the "record_size_limit"
    -- extension with this value to the server. A server sends back
    -- this extension with its own value if a client sends the
    -- extension. When negotiated, both my limit and peer's limit
    -- are enabled for protected communication.
    --
    -- Default: Nothing
    , limitHandshakeFragment :: Int
    -- ^ The limit to accept the number of each handshake message.
    -- For instance, a nasty client may send many fragments of client
    -- certificate.
    --
    -- Default: 32
    }
    deriving (Eq, Show)

-- | Default value for 'Limit'.
defaultLimit :: Limit
defaultLimit =
    Limit
        { limitRecordSize = Nothing
        , limitHandshakeFragment = 32
        }
