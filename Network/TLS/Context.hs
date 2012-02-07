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
import qualified Data.ByteString as B

import Control.Concurrent.MVar
import Control.Monad.State
import Control.Exception (throwIO, Exception(), onException)
import Data.IORef
import System.IO (Handle, hSetBuffering, BufferMode(..), hFlush)
import Prelude hiding (catch)

data TLSLogging = TLSLogging
	{ loggingPacketSent :: String -> IO ()
	, loggingPacketRecv :: String -> IO ()
	, loggingIOSent     :: Bytes -> IO ()
	, loggingIORecv     :: Header -> Bytes -> IO ()
	}

data TLSParams = TLSParams
	{ pConnectVersion    :: Version             -- ^ version to use on client connection.
	, pAllowedVersions   :: [Version]           -- ^ allowed versions that we can use.
	, pCiphers           :: [Cipher]            -- ^ all ciphers supported ordered by priority.
	, pCompressions      :: [Compression]       -- ^ all compression supported ordered by priority.
	, pWantClientCert    :: Bool                -- ^ request a certificate from client.
	                                            -- use by server only.
	, pUseSecureRenegotiation :: Bool           -- ^ notify that we want to use secure renegotation
	, pUseNextProtocolNegociation :: Bool       -- ^ use draft Next Protocol Negociation extension.
	, pUseSession             :: Bool           -- ^ generate new session if specified
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

-- | A TLS Context is a handle augmented by tls specific state and parameters
data TLSCtx a = TLSCtx
	{ ctxConnection      :: a             -- ^ return the connection object associated with this context
	, ctxParams          :: TLSParams
	, ctxState           :: MVar TLSState
	, ctxMeasurement     :: IORef Measurement
	, ctxEOF_            :: IORef Bool    -- ^ has the handle EOFed or not.
	, ctxEstablished_    :: IORef Bool    -- ^ has the handshake been done and been successful.
	, ctxConnectionFlush :: IO ()
	, ctxConnectionSend  :: Bytes -> IO ()
	, ctxConnectionRecv  :: Int -> IO Bytes
	}

updateMeasure :: MonadIO m => TLSCtx c -> (Measurement -> Measurement) -> m ()
updateMeasure ctx f = liftIO $ modifyIORef (ctxMeasurement ctx) f

withMeasure :: MonadIO m => TLSCtx c -> (Measurement -> IO a) -> m a
withMeasure ctx f = liftIO (readIORef (ctxMeasurement ctx) >>= f)

connectionFlush :: TLSCtx c -> IO ()
connectionFlush c = ctxConnectionFlush c

connectionSend :: TLSCtx c -> Bytes -> IO ()
connectionSend c b = updateMeasure c (addBytesSent $ B.length b) >> (ctxConnectionSend c) b

connectionRecv :: TLSCtx c -> Int -> IO Bytes
connectionRecv c sz = updateMeasure c (addBytesReceived sz) >> (ctxConnectionRecv c) sz

ctxEOF :: MonadIO m => TLSCtx a -> m Bool
ctxEOF ctx = liftIO (readIORef $ ctxEOF_ ctx)

setEOF :: MonadIO m => TLSCtx c -> m ()
setEOF ctx = liftIO $ writeIORef (ctxEOF_ ctx) True

ctxEstablished :: MonadIO m => TLSCtx a -> m Bool
ctxEstablished ctx = liftIO $ readIORef $ ctxEstablished_ ctx

setEstablished :: MonadIO m => TLSCtx c -> Bool -> m ()
setEstablished ctx v = liftIO $ writeIORef (ctxEstablished_ ctx) v

ctxLogging :: TLSCtx a -> TLSLogging
ctxLogging = pLogging . ctxParams

newCtxWith :: c -> IO () -> (Bytes -> IO ()) -> (Int -> IO Bytes) -> TLSParams -> TLSState -> IO (TLSCtx c)
newCtxWith c flushF sendF recvF params st = do
	stvar <- newMVar st
	eof   <- newIORef False
	established <- newIORef False
	stats <- newIORef newMeasurement
	return $ TLSCtx
		{ ctxConnection  = c
		, ctxParams      = params
		, ctxState       = stvar
		, ctxMeasurement = stats
		, ctxEOF_        = eof
		, ctxEstablished_    = established
		, ctxConnectionFlush = flushF
		, ctxConnectionSend  = sendF
		, ctxConnectionRecv  = recvF
		}

newCtx :: Handle -> TLSParams -> TLSState -> IO (TLSCtx Handle)
newCtx handle params st = do
	hSetBuffering handle NoBuffering
	newCtxWith handle (hFlush handle) (B.hPut handle) (B.hGet handle) params st

throwCore :: (MonadIO m, Exception e) => e -> m a
throwCore = liftIO . throwIO


usingState :: MonadIO m => TLSCtx c -> TLSSt a -> m (Either TLSError a)
usingState ctx f = liftIO (takeMVar mvar) >>= \st -> liftIO $ onException (execAndStore st) (putMVar mvar st)
	where
		mvar = ctxState ctx
		execAndStore st = do
			let (a, newst) = runTLSState f st
			putMVar mvar newst
			return a

usingState_ :: MonadIO m => TLSCtx c -> TLSSt a -> m a
usingState_ ctx f = do
	ret <- usingState ctx f
	case ret of
		Left err -> throwCore err
		Right r  -> return r

getStateRNG :: MonadIO m => TLSCtx c -> Int -> m Bytes
getStateRNG ctx n = usingState_ ctx (genTLSRandom n)

