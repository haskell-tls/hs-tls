-- |
-- Module      : Network.TLS.Core
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Core
	( TLSParams(..)
	, defaultParams
	, TLSCtx
	, newCtx
	, usingState
	, usingState_
	, getStateRNG
	, whileStatus
	, sendPacket
	, recvPacket
	, getParams
	, getHandle
	) where

import Network.TLS.Struct
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Crypto
import Network.TLS.Packet
import Network.TLS.State
import Network.TLS.Sending
import Network.TLS.Receiving
import Network.TLS.SRandom
import Data.Certificate.X509
import Data.List (intercalate)
import qualified Data.ByteString as B

import Control.Applicative ((<$>))
import Control.Concurrent.MVar
--import Control.Monad (when, unless)
import Control.Monad.State
import System.IO (Handle, hSetBuffering, BufferMode(..))

data TLSParams = TLSParams
	{ pConnectVersion    :: Version             -- ^ version to use on client connection.
	, pAllowedVersions   :: [Version]           -- ^ allowed versions that we can use.
	, pCiphers           :: [Cipher]            -- ^ all ciphers supported ordered by priority.
	, pCompressions      :: [Compression]       -- ^ all compression supported ordered by priority.
	, pWantClientCert    :: Bool                -- ^ request a certificate from client.
	                                            -- use by server only.
	, pCertificates      :: [(X509, Maybe PrivateKey)] -- ^ the cert chain for this context with the associated keys if any.
	, onCertificatesRecv :: ([X509] -> IO Bool) -- ^ callback to verify received cert chain.
	}

defaultParams :: TLSParams
defaultParams = TLSParams
	{ pConnectVersion    = TLS10
	, pAllowedVersions   = [TLS10,TLS11]
	, pCiphers           = []
	, pCompressions      = [nullCompression]
	, pWantClientCert    = False
	, pCertificates      = []
	, onCertificatesRecv = (\_ -> return True)
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

data TLSCtx = TLSCtx
	{ ctxHandle :: Handle
	, ctxParams :: TLSParams
	, ctxState  :: MVar TLSState
	}

newCtx :: Handle -> TLSParams -> TLSState -> IO TLSCtx
newCtx handle params state = do
	hSetBuffering handle NoBuffering
	stvar <- newMVar state
	return $ TLSCtx
		{ ctxHandle = handle
		, ctxParams = params
		, ctxState  = stvar
		}

usingState :: MonadIO m => TLSCtx -> TLSSt a -> m (Either TLSError a)
usingState ctx f = liftIO (takeMVar mvar) >>= execAndStore
	where
		mvar = ctxState ctx
		execAndStore st = do
			-- FIXME add onException with (putMVar mvar st)
			let (a, newst) = runTLSState f st
			liftIO (putMVar mvar newst)
			return a

usingState_ :: MonadIO m => TLSCtx -> TLSSt a -> m a
usingState_ ctx f = do
	ret <- usingState ctx f
	case ret of
		Left err -> error "assertion failed, error in path without an error"
		Right r  -> return r

getStateRNG :: MonadIO m => TLSCtx -> Int -> m Bytes
getStateRNG ctx n = usingState_ ctx (withTLSRNG (\rng -> getRandomBytes rng n))

whileStatus :: MonadIO m => TLSCtx -> (TLSStatus -> Bool) -> m a -> m ()
whileStatus ctx p a = do
	b <- usingState_ ctx (p . stStatus <$> get)
	when b (a >> whileStatus ctx p a)

recvPacket :: MonadIO m => TLSCtx -> m (Either TLSError [Packet])
recvPacket ctx = do
	hdr <- (liftIO $ B.hGet (ctxHandle ctx) 5) >>= return . decodeHeader
	case hdr of
		Left err                          -> return $ Left err
		Right header@(Header _ _ readlen) -> do
			content <- liftIO $ B.hGet (ctxHandle ctx) (fromIntegral readlen)
			usingState ctx $ readPacket header (EncryptedData content)

sendPacket :: MonadIO m => TLSCtx -> Packet -> m ()
sendPacket ctx pkt = do
	dataToSend <- usingState_ ctx $ writePacket pkt
	liftIO $ B.hPut (ctxHandle ctx) dataToSend

getParams :: TLSCtx -> TLSParams
getParams = ctxParams

getHandle :: TLSCtx -> Handle
getHandle = ctxHandle
