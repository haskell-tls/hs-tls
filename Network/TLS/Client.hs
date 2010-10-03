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
	( TLSClientParams(..)
	, TLSClientCallbacks(..)
	, TLSStateClient
	, TLSClient (..)
	, runTLSClient
	-- * low level packet sending receiving.
	, recvPacket
	, sendPacket
	-- * API, warning probably subject to change
	, connect
	, sendData
	, recvData
	, close
	) where

import Data.Maybe
import Data.Word
import Control.Applicative ((<$>))
import Control.Monad.Trans
import Control.Monad.State
import Data.Certificate.X509
import Network.TLS.Cipher
import Network.TLS.Struct
import Network.TLS.Packet
import Network.TLS.State
import Network.TLS.Sending
import Network.TLS.Receiving
import Network.TLS.SRandom
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import System.IO (Handle, hFlush)
import Data.List (find)

data TLSClientCallbacks = TLSClientCallbacks
	{ cbCertificates :: Maybe ([Certificate] -> IO Bool) -- ^ optional callback to verify certificates
	}

instance Show TLSClientCallbacks where
	show _ = "[callbacks]"

data TLSClientParams = TLSClientParams
	{ cpConnectVersion  :: Version            -- ^ client version we're sending by default
	, cpAllowedVersions :: [Version]          -- ^ allowed versions from the server
	, cpSession         :: Maybe [Word8]      -- ^ session for this connection
	, cpCiphers         :: [Cipher]           -- ^ all ciphers for this connection
	, cpCertificate     :: Maybe Certificate  -- ^ an optional client certificate
	, cpCallbacks       :: TLSClientCallbacks -- ^ user callbacks
	} deriving (Show)

data TLSStateClient = TLSStateClient
	{ scParams   :: TLSClientParams -- ^ client params and config for this connection
	, scTLSState :: TLSState        -- ^ client TLS State for this connection
	, scCertRequested :: Bool       -- ^ mark that the server requested a certificate
	} deriving (Show)

newtype TLSClient m a = TLSClient { runTLSC :: StateT TLSStateClient m a }
	deriving (Monad, MonadState TLSStateClient)

instance Monad m => MonadTLSState (TLSClient m) where
	getTLSState   = TLSClient (get >>= return . scTLSState)
	putTLSState s = TLSClient (get >>= put . (\st -> st { scTLSState = s }))

instance MonadTrans TLSClient where
	lift = TLSClient . lift

instance Monad m => Functor (TLSClient m) where
	fmap f = TLSClient . fmap f . runTLSC

runTLSClientST :: TLSClient m a -> TLSStateClient -> m (a, TLSStateClient)
runTLSClientST f s = runStateT (runTLSC f) s

runTLSClient :: TLSClient m a -> TLSClientParams -> SRandomGen -> m (a, TLSStateClient)
runTLSClient f params rng = runTLSClientST f (TLSStateClient { scParams = params, scTLSState = state, scCertRequested = False  })
	where state = (newTLSState rng) { stVersion = cpConnectVersion params, stClientContext = True }

{- | receive a single TLS packet or on error a TLSError -}
recvPacket :: Handle -> TLSClient IO (Either TLSError [Packet])
recvPacket handle = do
	hdr <- lift $ B.hGet handle 5 >>= return . decodeHeader
	case hdr of
		Left err                          -> return $ Left err
		Right header@(Header _ _ readlen) -> do
			content <- lift $ B.hGet handle (fromIntegral readlen)
			readPacket header (EncryptedData content)

{- | send a single TLS packet -}
sendPacket :: Handle -> Packet -> TLSClient IO ()
sendPacket handle pkt = do
	dataToSend <- writePacket pkt
	lift $ B.hPut handle dataToSend

processServerInfo :: Packet -> TLSClient IO ()
processServerInfo (Handshake (ServerHello ver _ _ cipher _ _)) = do
	ciphers <- cpCiphers . scParams <$> get
	allowedvers <- cpAllowedVersions . scParams <$> get
	case find ((==) ver) allowedvers of
		Nothing -> error ("received version which is not allowed: " ++ show ver)
		Just _  -> setVersion ver
	case find ((==) cipher . cipherID) ciphers of
		Nothing -> error "no cipher in common with the server"
		Just c  -> setCipher c

processServerInfo (Handshake (CertRequest _ _ _)) = do
	modify (\sc -> sc { scCertRequested = True })

processServerInfo (Handshake (Certificates certs)) = do
	callbacks <- cpCallbacks . scParams <$> get
	valid <- lift $ maybe (return True) (\cb -> cb certs) (cbCertificates callbacks)
	unless valid $ error "certificates received deemed invalid by user"

processServerInfo _ = return ()

recvServerInfo :: Handle -> TLSClient IO ()
recvServerInfo handle = do
	whileStatus (/= (StatusHandshake HsStatusServerHelloDone)) $ do
		pkts <- recvPacket handle
		case pkts of
			Left err -> error ("error received: " ++ show err)
			Right l  -> forM_ l processServerInfo

connectSendClientHello :: Handle -> TLSClient IO ()
connectSendClientHello handle  = do
	crand <- fromJust . clientRandom <$> withTLSRNG (\rng -> getRandomBytes rng 32)
	ver <- cpConnectVersion . scParams <$> get
	ciphers <- cpCiphers . scParams <$> get
	sendPacket handle $ Handshake (ClientHello ver crand (Session Nothing) (map cipherID ciphers) [ 0 ] Nothing)

connectSendClientCertificate :: Handle -> TLSClient IO ()
connectSendClientCertificate handle = do
	certRequested <- scCertRequested <$> get
	when certRequested $ do
		clientCert <- cpCertificate . scParams <$> get
		sendPacket handle $ Handshake (Certificates $ maybe [] (:[]) clientCert)

connectSendClientKeyXchg :: Handle -> TLSClient IO ()
connectSendClientKeyXchg handle = do
	prerand <- ClientKeyData . B.pack <$> withTLSRNG (\rng -> getRandomBytes rng 46)
	ver <- cpConnectVersion . scParams <$> get
	sendPacket handle $ Handshake (ClientKeyXchg ver prerand)

connectSendFinish :: Handle -> TLSClient IO ()
connectSendFinish handle = do
	cf <- getHandshakeDigest True
	sendPacket handle (Handshake $ Finished $ B.unpack cf)

{- | connect through a handle as a new TLS connection. -}
connect :: Handle -> TLSClient IO ()
connect handle = do
	connectSendClientHello handle
	recvServerInfo handle
	connectSendClientCertificate handle

	connectSendClientKeyXchg handle

	{- maybe send certificateVerify -}
	{- FIXME not implemented yet -}

	sendPacket handle (ChangeCipherSpec)
	lift $ hFlush handle

	{- send Finished -}
	connectSendFinish handle
	
	{- receive changeCipherSpec -}
	_ <- recvPacket handle

	{- receive Finished -}
	_ <- recvPacket handle

	return ()

sendDataChunk :: Handle -> B.ByteString -> TLSClient IO ()
sendDataChunk handle d =
	if B.length d > 16384
		then do
			let (sending, remain) = B.splitAt 16384 d
			sendPacket handle $ AppData sending
			sendDataChunk handle remain
		else
			sendPacket handle $ AppData d

{- | sendData sends a bunch of data -}
sendData :: Handle -> L.ByteString -> TLSClient IO ()
sendData handle d = mapM_ (sendDataChunk handle) (L.toChunks d)

{- | recvData get data out of Data packet, and automatically try to renegociate if
 - a Handshake HelloRequest is received -}
recvData :: Handle -> TLSClient IO L.ByteString
recvData handle = do
	pkt <- recvPacket handle
	case pkt of
		Right [AppData x] -> return $ L.fromChunks [x]
		Right [Handshake HelloRequest] -> connect handle >> recvData handle
		Left err          -> error ("error received: " ++ show err)
		_                 -> error "unexpected item"

{- | close a TLS connection.
 - note that it doesn't close the handle, but just signal we're going to close
 - the connection to the other side -}
close :: Handle -> TLSClient IO ()
close handle = do
	sendPacket handle $ Alert (AlertLevel_Warning, CloseNotify)
