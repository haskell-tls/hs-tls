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
import Data.Default.Class
import qualified Data.ByteString as B

type HostName = String

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
    }

defaultDebugParams :: DebugParams
defaultDebugParams = DebugParams
    { debugSeed = Nothing
    , debugPrintSeed = const (return ())
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
      -- ^ Server accepts this size of early data in TLS 1.3.
      -- 0 (or lower) means that the server does not accept early data.
    , serverEarlyDataSize     :: Int
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
    }

instance Default ServerParams where
    def = defaultParamsServer

-- | List all the supported algorithms, versions, ciphers, etc supported.
data Supported = Supported
    {
      -- | Supported Versions by this context
      -- On the client side, the highest version will be used to establish the connection.
      -- On the server side, the highest version that is less or equal than the client version will be chosed.
      supportedVersions       :: [Version]
      -- | Supported cipher methods.  The default is empty, specify a suitable
      -- cipher list.  'Network.TLS.Extra.Cipher.ciphersuite_default' is often
      -- a good choice.
    , supportedCiphers        :: [Cipher]
      -- | supported compressions methods
    , supportedCompressions   :: [Compression]
      -- | All supported hash/signature algorithms pair for client
      -- certificate verification and server signature in (EC)DHE,
      -- ordered by decreasing priority.
      --
      -- This list is sent to the peer as part of the signature_algorithms
      -- extension.  It is also used to restrict the choice of server
      -- credential, signature and hash algorithm, but only when the TLS
      -- version is 1.2 or above.  In order to disable SHA-1 one must then
      -- also disable earlier protocol versions in 'supportedVersions'.
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
      --   The default value is ['X25519','P256','P384','P521'].
      --   'X25519' and 'P256' provide 128-bit security which is strong
      --   enough until 2030.  Both curves are fast because their
      --   backends are written in C.
    , supportedGroups              :: [Group]
    } deriving (Show,Eq)

defaultSupported :: Supported
defaultSupported = Supported
    { supportedVersions       = [TLS12,TLS11,TLS10]
    , supportedCiphers        = []
    , supportedCompressions   = [nullCompression]
    , supportedHashSignatures = [ (HashIntrinsic,     SignatureRSApssRSAeSHA256)
                                , (HashIntrinsic,     SignatureRSApssRSAeSHA384)
                                , (HashIntrinsic,     SignatureRSApssRSAeSHA512)
                                , (Struct.HashSHA512, SignatureRSA)
                                , (Struct.HashSHA512, SignatureECDSA)
                                , (Struct.HashSHA384, SignatureRSA)
                                , (Struct.HashSHA384, SignatureECDSA)
                                , (Struct.HashSHA256, SignatureRSA)
                                , (Struct.HashSHA256, SignatureECDSA)
                                , (Struct.HashSHA1,   SignatureRSA)
                                , (Struct.HashSHA1,   SignatureDSS)
                                ]
    , supportedSecureRenegotiation = True
    , supportedClientInitiatedRenegotiation = False
    , supportedSession             = True
    , supportedFallbackScsv        = True
    , supportedEmptyPacket         = True
    , supportedGroups              = [X25519,P256,P384,P521]
    }

instance Default Supported where
    def = defaultSupported

data Shared = Shared
    { sharedCredentials     :: Credentials
    , sharedSessionManager  :: SessionManager
    , sharedCAStore         :: CertificateStore
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

defaultGroupUsage :: DHParams -> DHPublic -> IO GroupUsage
defaultGroupUsage params public
    | even $ dhParamsGetP params                   = return $ GroupUsageUnsupported "invalid odd prime"
    | not $ dhValid params (dhParamsGetG params)   = return $ GroupUsageUnsupported "invalid generator"
    | not $ dhValid params (dhUnwrapPublic public) = return   GroupUsageInvalidPublic
    | otherwise                                    = return   GroupUsageValid

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
      onCertificateRequest :: ([CertificateType],
                               Maybe [HashAndSignatureAlgorithm],
                               [DistinguishedName])
                           -> IO (Maybe (CertificateChain, PrivKey))
      -- | Used by the client to validate the server certificate.  The default
      -- implementation calls 'validateDefault' which validates according to the
      -- default hooks and checks provided by "Data.X509.Validation".  This can
      -- be replaced with a custom validation function using different settings.
      --
      -- The function is not expected to verify the key-usage extension of the
      -- end-entity certificate, as this depends on the dynamically-selected
      -- cipher and this part should not be cached.  Key-usage verification
      -- is performed by the library internally.
    , onServerCertificate  :: CertificateStore -> ValidationCache -> ServiceID -> CertificateChain -> IO [FailedReason]
      -- | This action is called when the client sends ClientHello
      --   to determine ALPN values such as '["h2", "http/1.1"]'.
    , onSuggestALPN :: IO (Maybe [B.ByteString])
      -- | This action is called to validate DHE parameters when
      --   the server selected a finite-field group not part of
      --   the "Supported Groups Registry".
      --   See RFC 7919 section 3.1 for recommandations.
    , onCustomFFDHEGroup :: DHParams -> DHPublic -> IO GroupUsage
    }

defaultClientHooks :: ClientHooks
defaultClientHooks = ClientHooks
    { onCertificateRequest = \ _ -> return Nothing
    , onServerCertificate  = validateDefault
    , onSuggestALPN        = return Nothing
    , onCustomFFDHEGroup   = defaultGroupUsage
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
      onClientCertificate :: CertificateChain -> IO CertificateUsage

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
    , onClientCertificate    = \_ -> return $ CertificateUsageReject $ CertificateRejectOther "no client certificates expected"
    , onUnverifiedClientCert = return False
    , onServerNameIndication = \_ -> return mempty
    , onNewHandshake         = \_ -> return True
    , onALPNClientSuggest    = Nothing
    }

instance Show ServerHooks where
    show _ = "ServerHooks"
instance Default ServerHooks where
    def = defaultServerHooks
