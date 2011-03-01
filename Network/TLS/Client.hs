{-# LANGUAGE GeneralizedNewtypeDeriving, MultiParamTypeClasses #-}

-- |
-- Module      : Network.TLS.Client
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Client module contains the necessary calls to create a connecting TLS socket
-- aka. a client socket.
--
module Network.TLS.Client
	( client
	-- * API, warning probably subject to change
	, initiate
	, sendData
	, recvData
	) where

import Data.Maybe
import Control.Monad.Trans
import Control.Monad.State
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Struct
import Network.TLS.State
import Network.TLS.SRandom
import Network.TLS.Core
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import System.IO (Handle, hFlush)
import Data.List (find)

client :: MonadIO m => TLSParams -> SRandomGen -> Handle -> m TLSCtx
client params rng handle = liftIO $ newCtx handle params state
	where state = (newTLSState rng) { stClientContext = True }

processServerInfo :: MonadIO m => TLSCtx -> Packet -> m ()
processServerInfo ctx (Handshake (ServerHello ver _ _ cipher _ _)) = do
	let ciphers     = pCiphers $ getParams ctx
	let allowedvers = pAllowedVersions $ getParams ctx

	case find ((==) ver) allowedvers of
		Nothing -> error ("received version which is not allowed: " ++ show ver)
		Just _  -> usingState_ ctx $ setVersion ver
	case find ((==) cipher . cipherID) ciphers of
		Nothing -> error "no cipher in common with the server"
		Just c  -> usingState_ ctx $ setCipher c

processServerInfo _ (Handshake (CertRequest _ _ _)) = do
	return ()
	--modify (\sc -> sc { scCertRequested = True })

processServerInfo ctx (Handshake (Certificates certs)) = do
	let cb = onCertificatesRecv $ getParams ctx
	valid <- liftIO $ cb certs
	unless valid $ error "certificates received deemed invalid by user"

processServerInfo _ _ = return ()

recvServerInfo :: MonadIO m => TLSCtx -> m ()
recvServerInfo ctx = do
	whileStatus ctx (/= (StatusHandshake HsStatusServerHelloDone)) $ do
		pkts <- recvPacket ctx
		case pkts of
			Left err -> error ("error received: " ++ show err)
			Right l  -> mapM_ (processServerInfo ctx) l

connectSendClientHello :: MonadIO m => TLSCtx -> m ()
connectSendClientHello ctx  = do
	crand <- getStateRNG ctx 32 >>= return . fromJust . clientRandom
	sendPacket ctx $ Handshake (ClientHello ver crand (Session Nothing) (map cipherID ciphers) (map compressionID compressions) Nothing)
	where
		params       = getParams ctx
		ver          = pConnectVersion params
		ciphers      = pCiphers params
		compressions = pCompressions params

connectSendClientCertificate :: MonadIO m => TLSCtx -> m ()
connectSendClientCertificate ctx = do
	certRequested <- return False -- scCertRequested <$> get
	when certRequested $ do
		let clientCerts = map fst $ pCertificates $ getParams ctx
		sendPacket ctx $ Handshake (Certificates clientCerts)

connectSendClientKeyXchg :: MonadIO m => TLSCtx -> m ()
connectSendClientKeyXchg ctx = do
	prerand <- getStateRNG ctx 46 >>= return . ClientKeyData
	let ver = pConnectVersion $ getParams ctx
	sendPacket ctx $ Handshake (ClientKeyXchg ver prerand)

connectSendFinish :: MonadIO m => TLSCtx -> m ()
connectSendFinish ctx = do
	cf <- usingState_ ctx $ getHandshakeDigest True
	sendPacket ctx (Handshake $ Finished $ B.unpack cf)

{- | initiate a new TLS connection through a handshake on a handle. -}
initiate :: MonadIO m => TLSCtx -> m ()
initiate handle = do
	connectSendClientHello handle
	recvServerInfo handle
	connectSendClientCertificate handle

	connectSendClientKeyXchg handle

	{- maybe send certificateVerify -}
	{- FIXME not implemented yet -}

	sendPacket handle (ChangeCipherSpec)
	liftIO $ hFlush $ getHandle handle

	{- send Finished -}
	connectSendFinish handle
	
	{- receive changeCipherSpec -}
	_ <- recvPacket handle

	{- receive Finished -}
	_ <- recvPacket handle

	return ()

{- | sendData sends a bunch of data -}
sendData :: MonadIO m => TLSCtx -> L.ByteString -> m ()
sendData ctx dataToSend = mapM_ sendDataChunk (L.toChunks dataToSend)
	where sendDataChunk d =
		if B.length d > 16384
			then do
				let (sending, remain) = B.splitAt 16384 d
				sendPacket ctx $ AppData sending
				sendDataChunk remain
			else
				sendPacket ctx $ AppData d


{- | recvData get data out of Data packet, and automatically renegociate if
 - a Handshake ClientHello is received -}
recvData :: MonadIO m => TLSCtx -> m L.ByteString
recvData handle = do
	pkt <- recvPacket handle
	case pkt of
		Right [AppData x] -> return $ L.fromChunks [x]
		Right [Handshake HelloRequest] -> initiate handle >> recvData handle
		Left err          -> error ("error received: " ++ show err)
		_                 -> error "unexpected item"
