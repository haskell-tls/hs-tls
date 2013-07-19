-- |
-- Module      : Network.TLS.Context
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- only needed because of some GHC bug relative to insufficient polymorphic field
{-# LANGUAGE RecordWildCards #-}
module Network.TLS.Context
    (
    -- * Context configuration
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

    -- * Context object and accessor
    , Backend(..)
    , Context
    , Hooks(..)
    , ctxParams
    , ctxConnection
    , ctxEOF
    , ctxHasSSLv2ClientHello
    , ctxDisableSSLv2ClientHello
    , ctxEstablished
    , ctxLogging
    , ctxWithHooks
    , setEOF
    , setEstablished
    , contextFlush
    , contextClose
    , contextSend
    , contextRecv
    , updateMeasure
    , withMeasure
    , withReadLock
    , withWriteLock
    , withStateLock

    -- * deprecated types
    , TLSParams
    , TLSLogging
    , TLSCertificateUsage
    , TLSCertificateRejectReason
    , TLSCtx

    -- * deprecated values
    , defaultParams

    -- * New contexts
    , contextNew
    , contextNewOnHandle

    -- * Context hooks
    , contextHookSetHandshakeRecv

    -- * Using context states
    , throwCore
    , usingState
    , usingState_
    , usingHState
    , getStateRNG
    ) where

import Network.BSD (HostName)
import Network.TLS.Extension
import Network.TLS.Struct
import qualified Network.TLS.Struct as Struct
import Network.TLS.Session
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Crypto
import Network.TLS.State
import Network.TLS.Handshake.State
import Network.TLS.Measurement
import Network.TLS.X509
import Data.List (intercalate)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Crypto.Random.API

import Control.Concurrent.MVar
import Control.Monad.State
import Control.Exception (throwIO, Exception())
import Data.IORef
import System.IO (Handle, hSetBuffering, BufferMode(..), hFlush, hClose)

data Logging = Logging
    { loggingPacketSent :: String -> IO ()
    , loggingPacketRecv :: String -> IO ()
    , loggingIOSent     :: B.ByteString -> IO ()
    , loggingIORecv     :: Header -> B.ByteString -> IO ()
    }

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
    , onNPNServerSuggest :: Maybe ([B.ByteString] -> IO B.ByteString)
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

      -- | suggested next protocols accoring to the next protocol negotiation extension.
    , onSuggestNextProtocols :: IO (Maybe [B.ByteString])
    }

data RoleParams = Client ClientParams | Server ServerParams

data Params = Params
    { pConnectVersion    :: Version             -- ^ version to use on client connection.
    , pAllowedVersions   :: [Version]           -- ^ allowed versions that we can use.
    , pCiphers           :: [Cipher]            -- ^ all ciphers supported ordered by priority.
    , pCompressions      :: [Compression]       -- ^ all compression supported ordered by priority.
    , pHashSignatures    :: [HashAndSignatureAlgorithm] -- ^ All supported hash/signature algorithms pair for client certificate verification, ordered by decreasing priority.
    , pUseSecureRenegotiation :: Bool           -- ^ notify that we want to use secure renegotation
    , pUseSession             :: Bool           -- ^ generate new session if specified
    , pCertificates      :: Maybe (CertificateChain, Maybe PrivKey) -- ^ the cert chain for this context with the associated keys if any.
    , pLogging           :: Logging             -- ^ callback for logging
    , onHandshake        :: Measurement -> IO Bool -- ^ callback on a beggining of handshake
    , onCertificatesRecv :: CertificateChain -> IO CertificateUsage -- ^ callback to verify received cert chain.
    , pSessionManager    :: SessionManager
    , roleParams         :: RoleParams
    }

-- | Set a new session manager in a parameters structure.
setSessionManager :: SessionManager -> Params -> Params
setSessionManager manager (Params {..}) = Params { pSessionManager = manager, .. }

withSessionManager :: Params -> (SessionManager -> a) -> a
withSessionManager (Params { pSessionManager = man }) f = f man

defaultLogging :: Logging
defaultLogging = Logging
    { loggingPacketSent = (\_ -> return ())
    , loggingPacketRecv = (\_ -> return ())
    , loggingIOSent     = (\_ -> return ())
    , loggingIORecv     = (\_ _ -> return ())
    }

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
    { pConnectVersion         = TLS10
    , pAllowedVersions        = [TLS10,TLS11,TLS12]
    , pCiphers                = []
    , pCompressions           = [nullCompression]
    , pHashSignatures         = [ (Struct.HashSHA512, SignatureRSA)
                                , (Struct.HashSHA384, SignatureRSA)
                                , (Struct.HashSHA256, SignatureRSA)
                                , (Struct.HashSHA224, SignatureRSA)
                                ]
    , pUseSecureRenegotiation = True
    , pUseSession             = True
    , pCertificates           = Nothing
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

defaultParams :: Params
defaultParams = defaultParamsClient
{-# DEPRECATED defaultParams "use defaultParamsClient" #-}


instance Show Params where
    show p = "Params { " ++ (intercalate "," $ map (\(k,v) -> k ++ "=" ++ v)
            [ ("connectVersion", show $ pConnectVersion p)
            , ("allowedVersions", show $ pAllowedVersions p)
            , ("ciphers", show $ pCiphers p)
            , ("compressions", show $ pCompressions p)
            , ("certificates", show $ pCertificates p)
            ]) ++ " }"


-- | Connection IO backend
data Backend = Backend
    { backendFlush :: IO ()                -- ^ Flush the connection sending buffer, if any.
    , backendClose :: IO ()                -- ^ Close the connection.
    , backendSend  :: ByteString -> IO ()  -- ^ Send a bytestring through the connection.
    , backendRecv  :: Int -> IO ByteString -- ^ Receive specified number of bytes from the connection.
    }

-- | A collection of hooks actions.
data Hooks = Hooks
    { hookRecvHandshake :: Handshake -> IO Handshake
    }

defaultHooks :: Hooks
defaultHooks = Hooks
    { hookRecvHandshake = \hs -> return hs
    }

-- | A TLS Context keep tls specific state, parameters and backend information.
data Context = Context
    { ctxConnection       :: Backend   -- ^ return the backend object associated with this context
    , ctxParams           :: Params
    , ctxState            :: MVar TLSState
    , ctxMeasurement      :: IORef Measurement
    , ctxEOF_             :: IORef Bool    -- ^ has the handle EOFed or not.
    , ctxEstablished_     :: IORef Bool    -- ^ has the handshake been done and been successful.
    , ctxSSLv2ClientHello :: IORef Bool    -- ^ enable the reception of compatibility SSLv2 client hello.
                                           -- the flag will be set to false regardless of its initial value
                                           -- after the first packet received.
    , ctxHooks            :: IORef Hooks   -- ^ hooks for this context
    , ctxLockWrite        :: MVar ()       -- ^ lock to use for writing data (including updating the state)
    , ctxLockRead         :: MVar ()       -- ^ lock to use for reading data (including updating the state)
    , ctxLockState        :: MVar ()       -- ^ lock used during read/write when receiving and sending packet.
                                           -- it is usually nested in a write or read lock.
    }

-- deprecated types, setup as aliases for compatibility.
type TLSParams = Params
type TLSCtx = Context
type TLSLogging = Logging
type TLSCertificateUsage = CertificateUsage
type TLSCertificateRejectReason = CertificateRejectReason

updateMeasure :: MonadIO m => Context -> (Measurement -> Measurement) -> m ()
updateMeasure ctx f = liftIO $ do
    x <- readIORef (ctxMeasurement ctx)
    writeIORef (ctxMeasurement ctx) $! f x

withMeasure :: MonadIO m => Context -> (Measurement -> IO a) -> m a
withMeasure ctx f = liftIO (readIORef (ctxMeasurement ctx) >>= f)

contextFlush :: Context -> IO ()
contextFlush = backendFlush . ctxConnection

contextClose :: Context -> IO ()
contextClose = backendClose . ctxConnection

contextSend :: Context -> Bytes -> IO ()
contextSend c b = updateMeasure c (addBytesSent $ B.length b) >> (backendSend $ ctxConnection c) b

contextRecv :: Context -> Int -> IO Bytes
contextRecv c sz = updateMeasure c (addBytesReceived sz) >> (backendRecv $ ctxConnection c) sz

ctxEOF :: MonadIO m => Context -> m Bool
ctxEOF ctx = liftIO (readIORef $ ctxEOF_ ctx)

ctxHasSSLv2ClientHello :: MonadIO m => Context -> m Bool
ctxHasSSLv2ClientHello ctx = liftIO (readIORef $ ctxSSLv2ClientHello ctx)

ctxDisableSSLv2ClientHello :: MonadIO m => Context -> m ()
ctxDisableSSLv2ClientHello ctx = liftIO (writeIORef (ctxSSLv2ClientHello ctx) False)

setEOF :: MonadIO m => Context -> m ()
setEOF ctx = liftIO $ writeIORef (ctxEOF_ ctx) True

ctxEstablished :: MonadIO m => Context -> m Bool
ctxEstablished ctx = liftIO $ readIORef $ ctxEstablished_ ctx

ctxWithHooks :: MonadIO m => Context -> (Hooks -> m a) -> m a
ctxWithHooks ctx f = liftIO (readIORef $ ctxHooks ctx) >>= f

setEstablished :: MonadIO m => Context -> Bool -> m ()
setEstablished ctx v = liftIO $ writeIORef (ctxEstablished_ ctx) v

ctxLogging :: Context -> Logging
ctxLogging = pLogging . ctxParams

-- | create a new context using the backend and parameters specified.
contextNew :: (MonadIO m, CPRG rng)
           => Backend   -- ^ Backend abstraction with specific method to interact with the connection type.
           -> Params    -- ^ Parameters of the context.
           -> rng       -- ^ Random number generator associated with this context.
           -> m Context
contextNew backend params rng = liftIO $ do
    let clientContext = case roleParams params of
                             Client {} -> True
                             Server {} -> False
    let st = newTLSState rng clientContext

    stvar <- newMVar st
    eof   <- newIORef False
    established <- newIORef False
    stats <- newIORef newMeasurement
    -- we enable the reception of SSLv2 ClientHello message only in the
    -- server context, where we might be dealing with an old/compat client.
    sslv2Compat <- newIORef (not clientContext)
    hooks <- newIORef defaultHooks
    lockWrite <- newMVar ()
    lockRead  <- newMVar ()
    lockState <- newMVar ()
    return $ Context
            { ctxConnection   = backend
            , ctxParams       = params
            , ctxState        = stvar
            , ctxMeasurement  = stats
            , ctxEOF_         = eof
            , ctxEstablished_ = established
            , ctxSSLv2ClientHello = sslv2Compat
            , ctxHooks            = hooks
            , ctxLockWrite        = lockWrite
            , ctxLockRead         = lockRead
            , ctxLockState        = lockState
            }

-- | create a new context on an handle.
contextNewOnHandle :: (MonadIO m, CPRG rng)
                   => Handle -- ^ Handle of the connection.
                   -> Params -- ^ Parameters of the context.
                   -> rng    -- ^ Random number generator associated with this context.
                   -> m Context
contextNewOnHandle handle params st =
    liftIO (hSetBuffering handle NoBuffering) >> contextNew backend params st
  where backend = Backend (hFlush handle) (hClose handle) (B.hPut handle) (B.hGet handle)

contextHookSetHandshakeRecv :: MonadIO m => Context -> (Handshake -> IO Handshake) -> m ()
contextHookSetHandshakeRecv context f =
    liftIO $ modifyIORef (ctxHooks context) (\hooks -> hooks { hookRecvHandshake = f })

throwCore :: (MonadIO m, Exception e) => e -> m a
throwCore = liftIO . throwIO

usingState :: MonadIO m => Context -> TLSSt a -> m (Either TLSError a)
usingState ctx f =
    liftIO $ modifyMVar (ctxState ctx) $ \st ->
            let (a, newst) = runTLSState f st
             in newst `seq` return (newst, a)

usingState_ :: MonadIO m => Context -> TLSSt a -> m a
usingState_ ctx f = do
    ret <- usingState ctx f
    case ret of
        Left err -> throwCore err
        Right r  -> return r

usingHState :: MonadIO m => Context -> HandshakeM a -> m a
usingHState ctx f = usingState_ ctx $ withHandshakeM f

getStateRNG :: MonadIO m => Context -> Int -> m Bytes
getStateRNG ctx n = usingState_ ctx $ genRandom n

withReadLock :: MonadIO m => Context -> IO a -> m a
withReadLock ctx f = liftIO $ withMVar (ctxLockRead ctx) (const f)

withWriteLock :: MonadIO m => Context -> IO a -> m a
withWriteLock ctx f = liftIO $ withMVar (ctxLockWrite ctx) (const f)

withStateLock :: MonadIO m => Context -> IO a -> m a
withStateLock ctx f = liftIO $ withMVar (ctxLockState ctx) (const f)
