-- |
-- Module      : Network.TLS.Context
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
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
        , Measurement(..)
        , CertificateUsage(..)
        , CertificateRejectReason(..)
        , defaultLogging
        , defaultParamsClient
        , defaultParamsServer

        -- * Context object and accessor
        , Backend(..)
        , Context
        , ctxParams
        , ctxConnection
        , ctxEOF
        , ctxEstablished
        , ctxLogging
        , setEOF
        , setEstablished
        , contextFlush
        , contextClose
        , contextSend
        , contextRecv
        , updateMeasure
        , withMeasure

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

        -- * Using context states
        , throwCore
        , usingState
        , usingState_
        , getStateRNG
        ) where

import Network.TLS.Struct
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Crypto
import Network.TLS.State
import Network.TLS.Measurement
import Data.Maybe
import Data.Certificate.X509
import Data.List (intercalate)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Crypto.Random

import Control.Concurrent.MVar
import Control.Monad.State
import Control.Exception (throwIO, Exception())
import Data.IORef
import System.IO (Handle, hSetBuffering, BufferMode(..), hFlush, hClose)
import Prelude hiding (catch)

data Logging = Logging
        { loggingPacketSent :: String -> IO ()
        , loggingPacketRecv :: String -> IO ()
        , loggingIOSent     :: B.ByteString -> IO ()
        , loggingIORecv     :: Header -> B.ByteString -> IO ()
        }

data ClientParams = ClientParams
data ServerParams = ServerParams

data RoleParams = Client ClientParams | Server ServerParams

data Params = Params
        { pConnectVersion    :: Version             -- ^ version to use on client connection.
        , pAllowedVersions   :: [Version]           -- ^ allowed versions that we can use.
        , pCiphers           :: [Cipher]            -- ^ all ciphers supported ordered by priority.
        , pCompressions      :: [Compression]       -- ^ all compression supported ordered by priority.
        , pWantClientCert    :: Bool                -- ^ request a certificate from client.
                                                    -- use by server only.
        , pUseSecureRenegotiation :: Bool           -- ^ notify that we want to use secure renegotation
        , pUseSession             :: Bool           -- ^ generate new session if specified
        , pCertificates      :: [(X509, Maybe PrivateKey)] -- ^ the cert chain for this context with the associated keys if any.
        , pLogging           :: Logging             -- ^ callback for logging
        , onHandshake        :: Measurement -> IO Bool -- ^ callback on a beggining of handshake
        , onCertificatesRecv :: [X509] -> IO CertificateUsage -- ^ callback to verify received cert chain.
        , onSessionResumption :: SessionID -> IO (Maybe SessionData) -- ^ callback to maybe resume session on server.
        , onSessionEstablished :: SessionID -> SessionData -> IO ()  -- ^ callback when session have been established
        , onSessionInvalidated :: SessionID -> IO ()                 -- ^ callback when session is invalidated by error
        , onSuggestNextProtocols :: IO (Maybe [B.ByteString])       -- ^ suggested next protocols accoring to the next protocol negotiation extension.
        , onNPNServerSuggest :: Maybe ([B.ByteString] -> IO B.ByteString)
        , sessionResumeWith   :: Maybe (SessionID, SessionData) -- ^ try to establish a connection using this session.
        , roleParams          :: RoleParams
        }

defaultLogging :: Logging
defaultLogging = Logging
        { loggingPacketSent = (\_ -> return ())
        , loggingPacketRecv = (\_ -> return ())
        , loggingIOSent     = (\_ -> return ())
        , loggingIORecv     = (\_ _ -> return ())
        }

defaultParamsClient :: Params
defaultParamsClient = Params
        { pConnectVersion         = TLS10
        , pAllowedVersions        = [TLS10,TLS11,TLS12]
        , pCiphers                = []
        , pCompressions           = [nullCompression]
        , pWantClientCert         = False
        , pUseSecureRenegotiation = True
        , pUseSession             = True
        , pCertificates           = []
        , pLogging                = defaultLogging
        , onHandshake             = (\_ -> return True)
        , onCertificatesRecv      = (\_ -> return CertificateUsageAccept)
        , onSessionResumption     = (\_ -> return Nothing)
        , onSessionEstablished    = (\_ _ -> return ())
        , onSessionInvalidated    = (\_ -> return ())
        , onSuggestNextProtocols  = return Nothing
        , onNPNServerSuggest      = Nothing
        , sessionResumeWith       = Nothing
        , roleParams              = Client $ ClientParams
        }

defaultParamsServer :: Params
defaultParamsServer = defaultParamsClient
        { roleParams = Server $ ServerParams
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
                , ("want-client-cert", show $ pWantClientCert p)
                , ("certificates", show $ length $ pCertificates p)
                ]) ++ " }"

-- | Certificate and Chain rejection reason
data CertificateRejectReason =
          CertificateRejectExpired
        | CertificateRejectRevoked
        | CertificateRejectUnknownCA
        | CertificateRejectOther String
        deriving (Show,Eq)

-- | Certificate Usage callback possible returns values.
data CertificateUsage =
          CertificateUsageAccept                         -- ^ usage of certificate accepted
        | CertificateUsageReject CertificateRejectReason -- ^ usage of certificate rejected
        deriving (Show,Eq)

-- |
data Backend = Backend
        { backendFlush :: IO ()                -- ^ Flush the connection sending buffer, if any.
        , backendClose :: IO ()                -- ^ Close the connection.
        , backendSend  :: ByteString -> IO ()  -- ^ Send a bytestring through the connection.
        , backendRecv  :: Int -> IO ByteString -- ^ Receive specified number of bytes from the connection.
        }

-- | A TLS Context keep tls specific state, parameters and backend information.
data Context = Context
        { ctxConnection      :: Backend   -- ^ return the backend object associated with this context
        , ctxParams          :: Params
        , ctxState           :: MVar TLSState
        , ctxMeasurement     :: IORef Measurement
        , ctxEOF_            :: IORef Bool    -- ^ has the handle EOFed or not.
        , ctxEstablished_    :: IORef Bool    -- ^ has the handshake been done and been successful.
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

setEOF :: MonadIO m => Context -> m ()
setEOF ctx = liftIO $ writeIORef (ctxEOF_ ctx) True

ctxEstablished :: MonadIO m => Context -> m Bool
ctxEstablished ctx = liftIO $ readIORef $ ctxEstablished_ ctx

setEstablished :: MonadIO m => Context -> Bool -> m ()
setEstablished ctx v = liftIO $ writeIORef (ctxEstablished_ ctx) v

ctxLogging :: Context -> Logging
ctxLogging = pLogging . ctxParams

-- | create a new context using the backend and parameters specified.
contextNew :: (MonadIO m, CryptoRandomGen rng)
           => Backend   -- ^ Backend abstraction with specific method to interacat with the connection type.
           -> Params    -- ^ Parameters of the context.
           -> rng       -- ^ Random number generator associated with this context.
           -> m Context
contextNew backend params rng = liftIO $ do

        let clientContext = case roleParams params of
                                 Client {} -> True
                                 Server {} -> False
        let st = (newTLSState rng) { stClientContext = clientContext }

        stvar <- newMVar st
        eof   <- newIORef False
        established <- newIORef False
        stats <- newIORef newMeasurement
        return $ Context
                { ctxConnection   = backend
                , ctxParams       = params
                , ctxState        = stvar
                , ctxMeasurement  = stats
                , ctxEOF_         = eof
                , ctxEstablished_ = established
                }

-- | create a new context on an handle.
contextNewOnHandle :: (MonadIO m, CryptoRandomGen rng)
                   => Handle -- ^ Handle of the connection.
                   -> Params -- ^ Parameters of the context.
                   -> rng    -- ^ Random number generator associated with this context.
                   -> m Context
contextNewOnHandle handle params st =
        liftIO (hSetBuffering handle NoBuffering) >> contextNew backend params st
        where backend = Backend (hFlush handle) (hClose handle) (B.hPut handle) (B.hGet handle)

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

getStateRNG :: MonadIO m => Context -> Int -> m Bytes
getStateRNG ctx n = usingState_ ctx (genTLSRandom n)

