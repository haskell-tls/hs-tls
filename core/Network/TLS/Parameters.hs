 {-# LANGUAGE CPP #-}

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
import Data.Default.Class
import qualified Data.ByteString as B
#if __GLASGOW_HASKELL__ < 710
import Data.Monoid (mempty)
#endif

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
    , clientServerIdentification      :: (HostName, Bytes)
      -- | Allow the use of the Server Name Indication TLS extension during handshake, which allow
      -- the client to specify which host name, it's trying to access. This is useful to distinguish
      -- CNAME aliasing (e.g. web virtual host).
    , clientUseServerNameIndication   :: Bool
      -- | try to establish a connection using this session.
    , clientWantSessionResume         :: Maybe (SessionID, SessionData)
    , clientShared                    :: Shared
    , clientHooks                     :: ClientHooks
    , clientSupported                 :: Supported
    , clientDebug                     :: DebugParams
    } deriving (Show)

defaultParamsClient :: HostName -> Bytes -> ClientParams
defaultParamsClient serverName serverId = ClientParams
    { clientWantSessionResume    = Nothing
    , clientUseMaxFragmentLength = Nothing
    , clientServerIdentification = (serverName, serverId)
    , clientUseServerNameIndication = True
    , clientShared               = def
    , clientHooks                = def
    , clientSupported            = def
    , clientDebug                = defaultDebugParams
    }

data ServerParams = ServerParams
    { -- | request a certificate from client.
      serverWantClientCert    :: Bool

      -- | This is a list of certificates from which the
      -- disinguished names are sent in certificate request
      -- messages.  For TLS1.0, it should not be empty.
    , serverCACertificates :: [SignedCertificate]

      -- | Server Optional Diffie Hellman parameters. If this value is not
      -- properly set, no Diffie Hellman key exchange will take place.
    , serverDHEParams         :: Maybe DHParams

    , serverShared            :: Shared
    , serverHooks             :: ServerHooks
    , serverSupported         :: Supported
    , serverDebug             :: DebugParams
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
      -- | Supported cipher methods
    , supportedCiphers        :: [Cipher]
      -- | supported compressions methods
    , supportedCompressions   :: [Compression]
      -- | All supported hash/signature algorithms pair for client
      -- certificate verification, ordered by decreasing priority.
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
      -- | A list of supported elliptic curves in the preferred order.
    , supportedCurves              :: [NamedCurve]
    } deriving (Show,Eq)

defaultSupported :: Supported
defaultSupported = Supported
    { supportedVersions       = [TLS12,TLS11,TLS10]
    , supportedCiphers        = []
    , supportedCompressions   = [nullCompression]
    , supportedHashSignatures = [ (Struct.HashSHA512, SignatureRSA)
                                , (Struct.HashSHA384, SignatureRSA)
                                , (Struct.HashSHA256, SignatureRSA)
                                , (Struct.HashSHA224, SignatureRSA)
                                , (Struct.HashSHA1,   SignatureRSA)
                                , (Struct.HashSHA1,   SignatureDSS)
                                ]
    , supportedSecureRenegotiation = True
    , supportedClientInitiatedRenegotiation = False
    , supportedSession             = True
    , supportedFallbackScsv        = True
    , supportedEmptyPacket         = True
    , supportedCurves              = [SEC SEC_p521r1, SEC SEC_p384r1, SEC SEC_p256r1]
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

-- | A set of callbacks run by the clients for various corners of TLS establishment
data ClientHooks = ClientHooks
    { -- | This action is called when the server sends a
      -- certificate request.  The parameter is the information
      -- from the request.  The action should select a certificate
      -- chain of one of the given certificate types where the
      -- last certificate in the chain should be signed by one of
      -- the given distinguished names.  Each certificate should
      -- be signed by the following one, except for the last.  At
      -- least the first of the certificates in the chain must
      -- have a corresponding private key, because that is used
      -- for signing the certificate verify message.
      --
      -- Note that is is the responsibility of this action to
      -- select a certificate matching one of the requested
      -- certificate types.  Returning a non-matching one will
      -- lead to handshake failure later.
      --
      -- Returning a certificate chain not matching the
      -- distinguished names may lead to problems or not,
      -- depending whether the server accepts it.
      onCertificateRequest :: ([CertificateType],
                               Maybe [HashAndSignatureAlgorithm],
                               [DistinguishedName]) -> IO (Maybe (CertificateChain, PrivKey))
    , onNPNServerSuggest   :: Maybe ([B.ByteString] -> IO B.ByteString)
    , onServerCertificate  :: CertificateStore -> ValidationCache -> ServiceID -> CertificateChain -> IO [FailedReason]
    , onSuggestALPN :: IO (Maybe [B.ByteString])
    }

defaultClientHooks :: ClientHooks
defaultClientHooks = ClientHooks
    { onCertificateRequest = \ _ -> return Nothing
    , onNPNServerSuggest   = Nothing
    , onServerCertificate  = validateDefault
    , onSuggestALPN        = return Nothing
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
      onClientCertificate :: CertificateChain -> IO CertificateUsage

      -- | This action is called when the client certificate
      -- cannot be verified.  A 'Nothing' argument indicates a
      -- wrong signature, a 'Just e' message signals a crypto
      -- error.
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
    , onServerNameIndication  :: Maybe HostName -> IO Credentials

      -- | suggested next protocols accoring to the next protocol negotiation extension.
    , onSuggestNextProtocols  :: IO (Maybe [B.ByteString])
      -- | at each new handshake, we call this hook to see if we allow handshake to happens.
    , onNewHandshake          :: Measurement -> IO Bool
    , onALPNClientSuggest     :: Maybe ([B.ByteString] -> IO B.ByteString)
    }

defaultServerHooks :: ServerHooks
defaultServerHooks = ServerHooks
    { onCipherChoosing       = \_ -> head
    , onClientCertificate    = \_ -> return $ CertificateUsageReject $ CertificateRejectOther "no client certificates expected"
    , onUnverifiedClientCert = return False
    , onServerNameIndication = \_ -> return mempty
    , onSuggestNextProtocols = return Nothing
    , onNewHandshake         = \_ -> return True
    , onALPNClientSuggest    = Nothing
    }

instance Show ServerHooks where
    show _ = "ServerHooks"
instance Default ServerHooks where
    def = defaultServerHooks
