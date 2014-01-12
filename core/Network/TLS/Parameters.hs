-- |
-- Module      : Network.TLS.Parameters
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- extension RecordWildCards only needed because of some GHC bug
-- relative to insufficient polymorphic field
{-# LANGUAGE RecordWildCards #-}
module Network.TLS.Parameters
    (
    -- * Parameters
      Params(..)
    , RoleParams(..)
    , ClientParams(..)
    , ServerParams(..)
    , updateClientParams
    , updateServerParams
    , Logging(..)
    , SessionID
    , SessionData(..)
    , MaxFragmentEnum(..)
    , Measurement(..)
    , CertificateUsage(..)
    , CertificateRejectReason(..)
    , defaultLogging
    , defaultParamsClient
    , defaultParamsServer
    , withSessionManager
    , setSessionManager
    , getClientParams
    , getServerParams
    , credentialsGet
    ) where

import Network.BSD (HostName)

import Network.TLS.Extension
import Network.TLS.Struct
import qualified Network.TLS.Struct as Struct
import Network.TLS.Session
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Crypto
import Network.TLS.Credentials
import Network.TLS.Hooks
import Network.TLS.Measurement
import Network.TLS.X509
import Data.Monoid
import Data.List (intercalate)
import qualified Data.ByteString as B

data ClientParams = ClientParams
    { clientUseMaxFragmentLength :: Maybe MaxFragmentEnum
    , clientUseServerName        :: Maybe HostName
    , clientWantSessionResume    :: Maybe (SessionID, SessionData) -- ^ try to establish a connection using this session.

      -- | This action is called when the server sends a
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
    , onCertificateRequest :: ([CertificateType],
                               Maybe [HashAndSignatureAlgorithm],
                               [DistinguishedName]) -> IO (Maybe (CertificateChain, PrivKey))
    , onNPNServerSuggest   :: Maybe ([B.ByteString] -> IO B.ByteString)
    }

data ServerParams = ServerParams
    { serverWantClientCert    :: Bool  -- ^ request a certificate from client.

      -- | This is a list of certificates from which the
      -- disinguished names are sent in certificate request
      -- messages.  For TLS1.0, it should not be empty.
    , serverCACertificates :: [SignedCertificate]

      -- | This action is called when a client certificate chain
      -- is received from the client.  When it returns a
      -- CertificateUsageReject value, the handshake is aborted.
    , onClientCertificate :: CertificateChain -> IO CertificateUsage

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

      -- | Server Optional Diffie Hellman parameters
    , serverDHEParams         :: Maybe DHParams

      -- | suggested next protocols accoring to the next protocol negotiation extension.
    , onSuggestNextProtocols :: IO (Maybe [B.ByteString])
    }

data RoleParams = Client ClientParams | Server ServerParams

data Params = Params
    { pAllowedVersions   :: [Version]           -- ^ allowed versions that we can use.
                                                -- the default version used for connection is the highest version in the list
    , pCiphers           :: [Cipher]            -- ^ all ciphers supported ordered by priority.
    , pCompressions      :: [Compression]       -- ^ all compression supported ordered by priority.
    , pHashSignatures    :: [HashAndSignatureAlgorithm] -- ^ All supported hash/signature algorithms pair for client certificate verification, ordered by decreasing priority.
    , pUseSecureRenegotiation :: Bool           -- ^ notify that we want to use secure renegotation
    , pUseSession             :: Bool           -- ^ generate new session if specified
    , pCertificates      :: Maybe (CertificateChain, Maybe PrivKey) -- ^ the cert chain for this context with the associated keys if any.
    , pCredentials       :: Credentials         -- ^ credentials
    , pLogging           :: Logging             -- ^ callback for logging
    , onHandshake        :: Measurement -> IO Bool -- ^ callback on a beggining of handshake
    , onCertificatesRecv :: CertificateChain -> IO CertificateUsage -- ^ callback to verify received cert chain.
    , pSessionManager    :: SessionManager
    , roleParams         :: RoleParams
    }
{-# DEPRECATED pCertificates "use pCredentials instead of pCertificates. removed in tls-1.3" #-}

credentialsGet :: Params -> Credentials
credentialsGet params = pCredentials params `mappend`
    case pCertificates params of
        Just (cchain, Just priv) -> Credentials [(cchain, priv)]
        _                        -> Credentials []

-- | Set a new session manager in a parameters structure.
setSessionManager :: SessionManager -> Params -> Params
setSessionManager manager (Params {..}) = Params { pSessionManager = manager, .. }

withSessionManager :: Params -> (SessionManager -> a) -> a
withSessionManager (Params { pSessionManager = man }) f = f man

getClientParams :: Params -> ClientParams
getClientParams params =
    case roleParams params of
        Client clientParams -> clientParams
        _                   -> error "server params in client context"

getServerParams :: Params -> ServerParams
getServerParams params =
    case roleParams params of
        Server serverParams -> serverParams
        _                   -> error "client params in server context"

defaultParamsClient :: Params
defaultParamsClient = Params
    { pAllowedVersions        = [TLS10,TLS11,TLS12]
    , pCiphers                = []
    , pCompressions           = [nullCompression]
    , pHashSignatures         = [ (Struct.HashSHA512, SignatureRSA)
                                , (Struct.HashSHA384, SignatureRSA)
                                , (Struct.HashSHA256, SignatureRSA)
                                , (Struct.HashSHA224, SignatureRSA)
                                , (Struct.HashSHA1,   SignatureDSS)
                                ]
    , pUseSecureRenegotiation = True
    , pUseSession             = True
    , pCertificates           = Nothing
    , pCredentials            = mempty
    , pLogging                = defaultLogging
    , onHandshake             = (\_ -> return True)
    , onCertificatesRecv      = (\_ -> return CertificateUsageAccept)
    , pSessionManager         = noSessionManager
    , roleParams              = Client $ ClientParams
                                    { clientWantSessionResume    = Nothing
                                    , clientUseMaxFragmentLength = Nothing
                                    , clientUseServerName        = Nothing
                                    , onCertificateRequest       = \ _ -> return Nothing
                                    , onNPNServerSuggest         = Nothing
                                    }
    }

defaultParamsServer :: Params
defaultParamsServer = defaultParamsClient { roleParams = Server role }
  where role = ServerParams
                   { serverWantClientCert   = False
                   , onCipherChoosing       = \_ -> head
                   , serverCACertificates   = []
                   , serverDHEParams        = Nothing
                   , onClientCertificate    = \ _ -> return $ CertificateUsageReject $ CertificateRejectOther "no client certificates expected"
                   , onUnverifiedClientCert = return False
                   , onSuggestNextProtocols  = return Nothing
                   }

updateRoleParams :: (ClientParams -> ClientParams) -> (ServerParams -> ServerParams) -> Params -> Params
updateRoleParams fc fs params = case roleParams params of
                                     Client c -> params { roleParams = Client (fc c) }
                                     Server s -> params { roleParams = Server (fs s) }

updateClientParams :: (ClientParams -> ClientParams) -> Params -> Params
updateClientParams f = updateRoleParams f id

updateServerParams :: (ServerParams -> ServerParams) -> Params -> Params
updateServerParams f = updateRoleParams id f

instance Show Params where
    show p = "Params { " ++ (intercalate "," $ map (\(k,v) -> k ++ "=" ++ v)
            [ ("allowedVersions", show $ pAllowedVersions p)
            , ("ciphers", show $ pCiphers p)
            , ("compressions", show $ pCompressions p)
            , ("certificates", show $ pCertificates p)
            ]) ++ " }"
