-- |
-- Module      : Network.TLS.Parameters
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Parameters
    (
      ClientParams(..)
    , ServerParams(..)
    , CommonParams
    , DebugParams(..)
    , ClientHooks(..)
    , OnCertificateRequest
    , OnServerCertificate
    , ServerHooks(..)
    , Supported(..)
    , Shared(..)
    -- * special default
    , defaultParamsClient
    -- * Parameters
    , MaxFragmentEnum(..)
    , GroupUsage(..)
    , CertificateUsage(..)
    , CertificateRejectReason(..)
    ) where

import Data.IORef

import Network.TLS.Extension
import Network.TLS.Struct
import qualified Network.TLS.Struct as Struct
import Network.TLS.Session
import Network.TLS.Cipher
import Network.TLS.Measurement
import Network.TLS.Compression
import Network.TLS.Crypto
import Network.TLS.Credentials
import Network.TLS.X509
import Network.TLS.RNG (Seed)
import Network.TLS.Imports
import Network.TLS.Types (HostName)
import Data.Default.Class
import qualified Data.ByteString as B


type CommonParams = (Supported, Shared, DebugParams)

-- | All settings should not be used in production
data DebugParams = DebugParams
    {
      -- | Disable the true randomness in favor of deterministic seed that will produce
      -- a deterministic random from. This is useful for tests and debugging purpose.
      -- Do not use in production
      debugSeed :: Maybe Seed
      -- | Add a way to print the seed that was randomly generated. re-using the same seed
      -- will reproduce the same randomness with 'debugSeed'
    , debugPrintSeed :: Seed -> IO ()
      -- | Force to choose this version in the server side.
    , debugVersionForced :: Maybe Version
      -- | Printing master keys. The default is no printing.
    , debugKeyLogger     :: String -> IO ()
    }

defaultDebugParams :: DebugParams
defaultDebugParams = DebugParams
    { debugSeed = Nothing
    , debugPrintSeed = const (return ())
    , debugVersionForced = Nothing
    , debugKeyLogger = \_ -> return ()
    }

instance Show DebugParams where
    show _ = "DebugParams"
instance Default DebugParams where
    def = defaultDebugParams

data ClientParams = ClientParams
    { clientUseMaxFragmentLength    :: Maybe MaxFragmentEnum
      -- | Define the name of the server, along with an extra service identification blob.
      -- this is important that the hostname part is properly filled for security reason,
      -- as it allow to properly associate the remote side with the given certificate
      -- during a handshake.
      --
      -- The extra blob is useful to differentiate services running on the same host, but that
      -- might have different certificates given. It's only used as part of the X509 validation
      -- infrastructure.
    , clientServerIdentification      :: (HostName, ByteString)
      -- | Allow the use of the Server Name Indication TLS extension during handshake, which allow
      -- the client to specify which host name, it's trying to access. This is useful to distinguish
      -- CNAME aliasing (e.g. web virtual host).
    , clientUseServerNameIndication   :: Bool
      -- | try to establish a connection using this session.
    , clientWantSessionResume         :: Maybe (SessionID, SessionData)
    , clientShared                    :: Shared
    , clientHooks                     :: ClientHooks
      -- | In this element, you'll  need to override the default empty value of
      -- of 'supportedCiphers' with a suitable cipherlist.
    , clientSupported                 :: Supported
    , clientDebug                     :: DebugParams
      -- | Client tries to send this early data in TLS 1.3 if possible.
      -- If not accepted by the server, it is application's responsibility
      -- to re-sent it.
    , clientEarlyData                 :: Maybe ByteString
    } deriving (Show)

defaultParamsClient :: HostName -> ByteString -> ClientParams
defaultParamsClient serverName serverId = ClientParams
    { clientWantSessionResume    = Nothing
    , clientUseMaxFragmentLength = Nothing
    , clientServerIdentification = (serverName, serverId)
    , clientUseServerNameIndication = True
    , clientShared               = def
    , clientHooks                = def
    , clientSupported            = def
    , clientDebug                = defaultDebugParams
    , clientEarlyData            = Nothing
    }

data ServerParams = ServerParams
    { -- | request a certificate from client.
      serverWantClientCert    :: Bool

      -- | This is a list of certificates from which the
      -- disinguished names are sent in certificate request
      -- messages.  For TLS1.0, it should not be empty.
    , serverCACertificates :: [SignedCertificate]

      -- | Server Optional Diffie Hellman parameters.  Setting parameters is
      -- necessary for FFDHE key exchange when clients are not compatible
      -- with RFC 7919.
      --
      -- Value can be one of the standardized groups from module
      -- "Network.TLS.Extra.FFDHE" or custom parameters generated with
      -- 'Crypto.PubKey.DH.generateParams'.
    , serverDHEParams         :: Maybe DHParams

    , serverShared            :: Shared
    , serverHooks             :: ServerHooks
    , serverSupported         :: Supported
    , serverDebug             :: DebugParams
      -- | Server accepts this size of early data in TLS 1.3.
      -- 0 (or lower) means that the server does not accept early data.
    , serverEarlyDataSize     :: Int
      -- | Lifetime in seconds for session tickets generated by the server.
      -- Acceptable value range is 0 to 604800 (7 days).  The default lifetime
      -- is 86400 seconds (1 day).
    , serverTicketLifetime    :: Int
    } deriving (Show)

defaultParamsServer :: ServerParams
defaultParamsServer = ServerParams
    { serverWantClientCert   = False
    , serverCACertificates   = []
    , serverDHEParams        = Nothing
    , serverHooks            = def
    , serverShared           = def
    , serverSupported        = def
    , serverDebug            = defaultDebugParams
    , serverEarlyDataSize    = 0
    , serverTicketLifetime   = 86400
    }

instance Default ServerParams where
    def = defaultParamsServer

-- | List all the supported algorithms, versions, ciphers, etc supported.
data Supported = Supported
    {
      -- | Supported versions by this context.  On the client side, the highest
      -- version will be used to establish the connection.  On the server side,
      -- the highest version that is less or equal than the client version will
      -- be chosen.
      --
      -- Versions should be listed in preference order, i.e. higher versions
      -- first.
      supportedVersions       :: [Version]
      -- | Supported cipher methods.  The default is empty, specify a suitable
      -- cipher list.  'Network.TLS.Extra.Cipher.ciphersuite_default' is often
      -- a good choice.
    , supportedCiphers        :: [Cipher]
      -- | Supported compressions methods.  By default only the "null"
      -- compression is supported, which means no compression will be performed.
      -- Allowing other compression method is not advised as it causes a
      -- connection failure when TLS 1.3 is negotiated.
    , supportedCompressions   :: [Compression]
      -- | All supported hash/signature algorithms pair for client
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
      -- PKCS#1, DSS.
    , supportedHashSignatures :: [HashAndSignatureAlgorithm]
      -- | Secure renegotiation defined in RFC5746.
      --   If 'True', clients send the renegotiation_info extension.
      --   If 'True', servers handle the extension or the renegotiation SCSV
      --   then send the renegotiation_info extension.
    , supportedSecureRenegotiation :: Bool
      -- | If 'True', renegotiation is allowed from the client side.
      --   This is vulnerable to DOS attacks.
      --   If 'False', renegotiation is allowed only from the server side
      --   via HelloRequest.
    , supportedClientInitiatedRenegotiation :: Bool
      -- | Set if we support session.
    , supportedSession             :: Bool
      -- | Support for fallback SCSV defined in RFC7507.
      --   If 'True', servers reject handshakes which suggest
      --   a lower protocol than the highest protocol supported.
    , supportedFallbackScsv        :: Bool
      -- | In ver <= TLS1.0, block ciphers using CBC are using CBC residue as IV, which can be guessed
      -- by an attacker. Hence, an empty packet is normally sent before a normal data packet, to
      -- prevent guessability. Some Microsoft TLS-based protocol implementations, however,
      -- consider these empty packets as a protocol violation and disconnect. If this parameter is
      -- 'False', empty packets will never be added, which is less secure, but might help in rare
      -- cases.
    , supportedEmptyPacket         :: Bool
      -- | A list of supported elliptic curves and finite-field groups in the
      --   preferred order.
      --
      --   The list is sent to the server as part of the "supported_groups"
      --   extension.  It is used in both clients and servers to restrict
      --   accepted groups in DH key exchange.
      --
      --   The default value includes all groups with security strength of 128
      --   bits or more.
    , supportedGroups              :: [Group]
    } deriving (Show,Eq)

defaultSupported :: Supported
defaultSupported = Supported
    { supportedVersions       = [TLS13,TLS12,TLS11,TLS10]
    , supportedCiphers        = []
    , supportedCompressions   = [nullCompression]
    , supportedHashSignatures = [ (HashIntrinsic,     SignatureEd448)
                                , (HashIntrinsic,     SignatureEd25519)
                                , (Struct.HashSHA256, SignatureECDSA)
                                , (Struct.HashSHA384, SignatureECDSA)
                                , (Struct.HashSHA512, SignatureECDSA)
                                , (HashIntrinsic,     SignatureRSApssRSAeSHA512)
                                , (HashIntrinsic,     SignatureRSApssRSAeSHA384)
                                , (HashIntrinsic,     SignatureRSApssRSAeSHA256)
                                , (Struct.HashSHA512, SignatureRSA)
                                , (Struct.HashSHA384, SignatureRSA)
                                , (Struct.HashSHA256, SignatureRSA)
                                , (Struct.HashSHA1,   SignatureRSA)
                                , (Struct.HashSHA1,   SignatureDSS)
                                ]
    , supportedSecureRenegotiation = True
    , supportedClientInitiatedRenegotiation = False
    , supportedSession             = True
    , supportedFallbackScsv        = True
    , supportedEmptyPacket         = True
    , supportedGroups              = [X25519,X448,P256,FFDHE3072,FFDHE4096,P384,FFDHE6144,FFDHE8192,P521]
    }

instance Default Supported where
    def = defaultSupported

-- | Parameters that are common to clients and servers.
data Shared = Shared
    { -- | The list of certificates and private keys that a server will use as
      -- part of authentication to clients.  Actual credentials that are used
      -- are selected dynamically from this list based on client capabilities.
      -- Additional credentials returned by 'onServerNameIndication' are also
      -- considered.
      --
      -- When credential list is left empty (the default value), no key
      -- exchange can take place.
      sharedCredentials     :: Credentials
      -- | Callbacks used by clients and servers in order to resume TLS
      -- sessions.  The default implementation never resumes sessions.  Package
      -- <https://hackage.haskell.org/package/tls-session-manager tls-session-manager>
      -- provides an in-memory implementation.
    , sharedSessionManager  :: SessionManager
      -- | A collection of trust anchors to be used by a client as
      -- part of validation of server certificates.  This is set as
      -- first argument to function 'onServerCertificate'.  Package
      -- <https://hackage.haskell.org/package/x509-system x509-system>
      -- gives access to a default certificate store configured in the
      -- system.
    , sharedCAStore         :: CertificateStore
      -- | Callbacks that may be used by a client to cache certificate
      -- validation results (positive or negative) and avoid expensive
      -- signature check.  The default implementation does not have
      -- any caching.
    , sharedValidationCache :: ValidationCache
    }

instance Show Shared where
    show _ = "Shared"
instance Default Shared where
    def = Shared
            { sharedCAStore         = mempty
            , sharedCredentials     = mempty
            , sharedSessionManager  = noSessionManager
            , sharedValidationCache = def
            }

-- | Group usage callback possible return values.
data GroupUsage =
          GroupUsageValid                 -- ^ usage of group accepted
        | GroupUsageInsecure              -- ^ usage of group provides insufficient security
        | GroupUsageUnsupported String    -- ^ usage of group rejected for other reason (specified as string)
        | GroupUsageInvalidPublic         -- ^ usage of group with an invalid public value
        deriving (Show,Eq)

defaultGroupUsage :: Int -> DHParams -> DHPublic -> IO GroupUsage
defaultGroupUsage minBits params public
    | even $ dhParamsGetP params                   = return $ GroupUsageUnsupported "invalid odd prime"
    | not $ dhValid params (dhParamsGetG params)   = return $ GroupUsageUnsupported "invalid generator"
    | not $ dhValid params (dhUnwrapPublic public) = return   GroupUsageInvalidPublic
    -- To prevent Logjam attack
    | dhParamsGetBits params < minBits             = return   GroupUsageInsecure
    | otherwise                                    = return   GroupUsageValid

-- | Type for 'onCertificateRequest'. This type synonym is to make
--   document readable.
type OnCertificateRequest = ([CertificateType],
                             Maybe [HashAndSignatureAlgorithm],
                             [DistinguishedName])
                           -> IO (Maybe (CertificateChain, PrivKey))

-- | Type for 'onServerCertificate'. This type synonym is to make
--   document readable.
type OnServerCertificate = CertificateStore -> ValidationCache -> ServiceID -> CertificateChain -> IO [FailedReason]

-- | A set of callbacks run by the clients for various corners of TLS establishment
data ClientHooks = ClientHooks
    { -- | This action is called when the a certificate request is
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
      onCertificateRequest :: OnCertificateRequest
      -- | Used by the client to validate the server certificate.  The default
      -- implementation calls 'validateDefault' which validates according to the
      -- default hooks and checks provided by "Data.X509.Validation".  This can
      -- be replaced with a custom validation function using different settings.
      --
      -- The function is not expected to verify the key-usage extension of the
      -- end-entity certificate, as this depends on the dynamically-selected
      -- cipher and this part should not be cached.  Key-usage verification
      -- is performed by the library internally.
    , onServerCertificate  :: OnServerCertificate
      -- | This action is called when the client sends ClientHello
      --   to determine ALPN values such as '["h2", "http/1.1"]'.
    , onSuggestALPN :: IO (Maybe [B.ByteString])
      -- | This action is called to validate DHE parameters when the server
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
    , onCustomFFDHEGroup :: DHParams -> DHPublic -> IO GroupUsage
    }

defaultClientHooks :: ClientHooks
defaultClientHooks = ClientHooks
    { onCertificateRequest = \ _ -> return Nothing
    , onServerCertificate  = validateDefault
    , onSuggestALPN        = return Nothing
    , onCustomFFDHEGroup   = defaultGroupUsage 1024
    }

instance Show ClientHooks where
    show _ = "ClientHooks"
instance Default ClientHooks where
    def = defaultClientHooks

-- | A set of callbacks run by the server for various corners of the TLS establishment
data ServerHooks = ServerHooks
    {
      -- | This action is called when a client certificate chain
      -- is received from the client.  When it returns a
      -- CertificateUsageReject value, the handshake is aborted.
      --
      -- The function is not expected to verify the key-usage
      -- extension of the certificate.  This verification is
      -- performed by the library internally.
      onClientCertificate :: CertificateChain -> IORef (Maybe CertificateChain) -> IO CertificateUsage

      -- | This action is called when the client certificate
      -- cannot be verified. Return 'True' to accept the certificate
      -- anyway, or 'False' to fail verification.
    , onUnverifiedClientCert :: IO Bool

      -- | Allow the server to choose the cipher relative to the
      -- the client version and the client list of ciphers.
      --
      -- This could be useful with old clients and as a workaround
      -- to the BEAST (where RC4 is sometimes prefered with TLS < 1.1)
      --
      -- The client cipher list cannot be empty.
    , onCipherChoosing        :: Version -> [Cipher] -> Cipher

      -- | Allow the server to indicate additional credentials
      -- to be used depending on the host name indicated by the
      -- client.
      --
      -- This is most useful for transparent proxies where
      -- credentials must be generated on the fly according to
      -- the host the client is trying to connect to.
      --
      -- Returned credentials may be ignored if a client does not support
      -- the signature algorithms used in the certificate chain.
    , onServerNameIndication  :: Maybe HostName -> IO Credentials

      -- | at each new handshake, we call this hook to see if we allow handshake to happens.
    , onNewHandshake          :: Measurement -> IO Bool

      -- | Allow the server to choose an application layer protocol
      --   suggested from the client through the ALPN
      --   (Application Layer Protocol Negotiation) extensions.
    , onALPNClientSuggest     :: Maybe ([B.ByteString] -> IO B.ByteString)
    }

defaultServerHooks :: ServerHooks
defaultServerHooks = ServerHooks
    { onCipherChoosing       = \_ -> head
    , onClientCertificate    = \_ _ -> return $ CertificateUsageReject $ CertificateRejectOther "no client certificates expected"
    , onUnverifiedClientCert = return False
    , onServerNameIndication = \_ -> return mempty
    , onNewHandshake         = \_ -> return True
    , onALPNClientSuggest    = Nothing
    }

instance Show ServerHooks where
    show _ = "ServerHooks"
instance Default ServerHooks where
    def = defaultServerHooks
