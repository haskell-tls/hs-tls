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
	  TLSParams(..)
	, TLSLogging(..)
	, SessionData(..)
	, Measurement(..)
	, TLSCertificateUsage(..)
	, TLSCertificateRejectReason(..)
	, defaultLogging
	, defaultParams

	-- * Context object and accessor
	, TLSBackend(..)
	, TLSCtx
	, ctxParams
	, ctxConnection
	, ctxEOF
	, ctxEstablished
	, ctxLogging
	, setEOF
	, setEstablished
	, connectionFlush
	, connectionSend
	, connectionRecv
	, updateMeasure
	, withMeasure

	-- * New contexts
	, newCtxWith
	, newCtx

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

import Control.Concurrent.MVar
import Control.Monad.State
import Control.Exception (throwIO, Exception())
import Data.IORef
import System.IO (Handle, hSetBuffering, BufferMode(..), hFlush)
import Prelude hiding (catch)

data TLSLogging = TLSLogging
	{ loggingPacketSent :: String -> IO ()
	, loggingPacketRecv :: String -> IO ()
	, loggingIOSent     :: B.ByteString -> IO ()
	, loggingIORecv     :: Header -> B.ByteString -> IO ()
	}

data TLSParams = TLSParams
	{ pConnectVersion    :: Version             -- ^ version to use on client connection.
	, pAllowedVersions   :: [Version]           -- ^ allowed versions that we can use.
	, pCiphers           :: [Cipher]            -- ^ all ciphers supported ordered by priority.
	, pCompressions      :: [Compression]       -- ^ all compression supported ordered by priority.
	, pWantClientCert    :: Bool                -- ^ request a certificate from client.
	                                            -- use by server only.
	, pUseSecureRenegotiation :: Bool           -- notify that we want to use secure renegotation
	, pUseSession             :: Bool           -- generate new session if specified
	, pCertificates      :: [(X509, Maybe PrivateKey)] -- ^ the cert chain for this context with the associated keys if any.
	, pLogging           :: TLSLogging          -- ^ callback for logging
	, onHandshake        :: Measurement -> IO Bool -- ^ callback on a beggining of handshake
	, onCertificatesRecv :: [X509] -> IO TLSCertificateUsage -- ^ callback to verify received cert chain.
	, onSessionResumption :: SessionID -> IO (Maybe SessionData) -- ^ callback to maybe resume session on server.
	, onSessionEstablished :: SessionID -> SessionData -> IO ()  -- ^ callback when session have been established
	, onSessionInvalidated :: SessionID -> IO ()                 -- ^ callback when session is invalidated by error
	, sessionResumeWith   :: Maybe (SessionID, SessionData) -- ^ try to establish a connection using this session.
	}

defaultLogging :: TLSLogging
defaultLogging = TLSLogging
	{ loggingPacketSent = (\_ -> return ())
	, loggingPacketRecv = (\_ -> return ())
	, loggingIOSent     = (\_ -> return ())
	, loggingIORecv     = (\_ _ -> return ())
	}

defaultParams :: TLSParams
defaultParams = TLSParams
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
	, sessionResumeWith       = Nothing
	}

instance Show TLSParams where
	show p = "TLSParams { " ++ (intercalate "," $ map (\(k,v) -> k ++ "=" ++ v)
		[ ("connectVersion", show $ pConnectVersion p)
		, ("allowedVersions", show $ pAllowedVersions p)
		, ("ciphers", show $ pCiphers p)
		, ("compressions", show $ pCompressions p)
		, ("want-client-cert", show $ pWantClientCert p)
		, ("certificates", show $ length $ pCertificates p)
		]) ++ " }"

-- | Certificate and Chain rejection reason
data TLSCertificateRejectReason =
	  CertificateRejectExpired
	| CertificateRejectRevoked
	| CertificateRejectUnknownCA
	| CertificateRejectOther String
	deriving (Show,Eq)

-- | Certificate Usage callback possible returns values.
data TLSCertificateUsage =
	  CertificateUsageAccept                            -- ^ usage of certificate accepted
	| CertificateUsageReject TLSCertificateRejectReason -- ^ usage of certificate rejected
	deriving (Show,Eq)

-- |
data TLSBackend = TLSBackend
	{ backendFlush :: IO ()                -- ^ Flush the connection sending buffer, if any.
	, backendSend  :: ByteString -> IO ()  -- ^ Send a bytestring through the connection.
	, backendRecv  :: Int -> IO ByteString -- ^ Receive specified number of bytes from the connection.
	}

-- | A TLS Context keep tls specific state, parameters and backend information.
data TLSCtx = TLSCtx
	{ ctxConnection      :: TLSBackend   -- ^ return the backend object associated with this context
	, ctxParams          :: TLSParams
	, ctxState           :: MVar TLSState
	, ctxMeasurement     :: IORef Measurement
	, ctxEOF_            :: IORef Bool    -- ^ has the handle EOFed or not.
	, ctxEstablished_    :: IORef Bool    -- ^ has the handshake been done and been successful.
	}

updateMeasure :: MonadIO m => TLSCtx -> (Measurement -> Measurement) -> m ()
updateMeasure ctx f = liftIO $ do
    x <- readIORef (ctxMeasurement ctx)
    writeIORef (ctxMeasurement ctx) $! f x

withMeasure :: MonadIO m => TLSCtx -> (Measurement -> IO a) -> m a
withMeasure ctx f = liftIO (readIORef (ctxMeasurement ctx) >>= f)

connectionFlush :: TLSCtx -> IO ()
connectionFlush = backendFlush . ctxConnection

connectionSend :: TLSCtx -> Bytes -> IO ()
connectionSend c b = updateMeasure c (addBytesSent $ B.length b) >> (backendSend $ ctxConnection c) b

connectionRecv :: TLSCtx -> Int -> IO Bytes
connectionRecv c sz = updateMeasure c (addBytesReceived sz) >> (backendRecv $ ctxConnection c) sz

ctxEOF :: MonadIO m => TLSCtx -> m Bool
ctxEOF ctx = liftIO (readIORef $ ctxEOF_ ctx)

setEOF :: MonadIO m => TLSCtx -> m ()
setEOF ctx = liftIO $ writeIORef (ctxEOF_ ctx) True

ctxEstablished :: MonadIO m => TLSCtx -> m Bool
ctxEstablished ctx = liftIO $ readIORef $ ctxEstablished_ ctx

setEstablished :: MonadIO m => TLSCtx -> Bool -> m ()
setEstablished ctx v = liftIO $ writeIORef (ctxEstablished_ ctx) v

ctxLogging :: TLSCtx -> TLSLogging
ctxLogging = pLogging . ctxParams

newCtxWith :: TLSBackend -> TLSParams -> TLSState -> IO TLSCtx
newCtxWith backend params st = do
	stvar <- newMVar st
	eof   <- newIORef False
	established <- newIORef False
	stats <- newIORef newMeasurement
	return $ TLSCtx
		{ ctxConnection   = backend
		, ctxParams       = params
		, ctxState        = stvar
		, ctxMeasurement  = stats
		, ctxEOF_         = eof
		, ctxEstablished_ = established
		}

newCtx :: Handle -> TLSParams -> TLSState -> IO TLSCtx
newCtx handle params st =
	hSetBuffering handle NoBuffering >> newCtxWith backend params st
	where backend = TLSBackend (hFlush handle) (B.hPut handle) (B.hGet handle)

throwCore :: (MonadIO m, Exception e) => e -> m a
throwCore = liftIO . throwIO


usingState :: MonadIO m => TLSCtx -> TLSSt a -> m (Either TLSError a)
usingState ctx f =
	liftIO $ modifyMVar (ctxState ctx) $ \st ->
		let (a, newst) = runTLSState f st
		 in newst `seq` return (newst, a)

usingState_ :: MonadIO m => TLSCtx -> TLSSt a -> m a
usingState_ ctx f = do
	ret <- usingState ctx f
	case ret of
		Left err -> throwCore err
		Right r  -> return r

getStateRNG :: MonadIO m => TLSCtx -> Int -> m Bytes
getStateRNG ctx n = usingState_ ctx (genTLSRandom n)

