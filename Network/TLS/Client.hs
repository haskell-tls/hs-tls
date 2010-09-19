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
	where state = (newTLSState rng) { stVersion = TLS10, stClientContext = True }

{- | receive a single TLS packet or on error a TLSError -}
recvPacket :: Handle -> TLSClient IO (Either TLSError Packet)
recvPacket handle = do
	hdr <- lift $ L.hGet handle 5 >>= return . decodeHeader
	case hdr of
		Left err                          -> return $ Left err
		Right header@(Header _ _ readlen) -> do
			content <- lift $ L.hGet handle (fromIntegral readlen)
			readPacket header (EncryptedData content)

{- | send a single TLS packet -}
sendPacket :: Handle -> Packet -> TLSClient IO ()
sendPacket handle pkt = do
	dataToSend <- writePacket pkt
	lift $ L.hPut handle dataToSend

recvServerHello :: Handle -> TLSClient IO ()
recvServerHello handle = do
	ciphers <- fmap (cpCiphers . scParams) get
	allowedvers <- fmap (cpAllowedVersions . scParams) get
	callbacks <- fmap (cpCallbacks . scParams) get
	pkt <- recvPacket handle
	let hs = case pkt of
		Right (Handshake h) -> h
		Left err            -> error ("error received: " ++ show err)
		Right x             -> error ("unexpected packet received, expecting handshake " ++ show x)
	case hs of
		ServerHello ver _ _ cipher _ _ -> do
			case find ((==) ver) allowedvers of
				Nothing -> error ("received version which is not allowed: " ++ show ver)
				Just _  -> setVersion ver

			case find ((==) cipher . cipherID) ciphers of
				Nothing -> error "no cipher in common with the server"
				Just c  -> setCipher c
			recvServerHello handle
		CertRequest _ _ _  -> modify (\sc -> sc { scCertRequested = True }) >> recvServerHello handle
		Certificates certs -> do
			valid <- lift $ maybe (return True) (\cb -> cb certs) (cbCertificates callbacks)
			unless valid $ error "certificates received deemed invalid by user"
			recvServerHello handle
		ServerHelloDone    -> return ()
		_                  -> error "unexpected handshake message received in server hello messages"

connectSendClientHello :: Handle -> ClientRandom -> TLSClient IO ()
connectSendClientHello handle crand = do
	ver <- fmap (cpConnectVersion . scParams) get
	ciphers <- fmap (cpCiphers . scParams) get
	sendPacket handle $ Handshake (ClientHello ver crand (Session Nothing) (map cipherID ciphers) [ 0 ] Nothing)

connectSendClientCertificate :: Handle -> TLSClient IO ()
connectSendClientCertificate handle = do
	certRequested <- fmap scCertRequested get
	when certRequested $ do
		clientCert <- fmap (cpCertificate . scParams) get
		sendPacket handle $ Handshake (Certificates $ maybe [] (:[]) clientCert)

connectSendClientKeyXchg :: Handle -> ClientKeyData -> TLSClient IO ()
connectSendClientKeyXchg handle prerand = do
	ver <- fmap (cpConnectVersion . scParams) get
	sendPacket handle $ Handshake (ClientKeyXchg ver prerand)

connectSendFinish :: Handle -> TLSClient IO ()
connectSendFinish handle = do
	cf <- getHandshakeDigest True
	sendPacket handle (Handshake $ Finished $ L.unpack cf)

{- | connect through a handle as a new TLS connection. -}
connect :: Handle -> ClientRandom -> ClientKeyData -> TLSClient IO ()
connect handle crand premasterRandom = do
	connectSendClientHello handle crand
	recvServerHello handle
	connectSendClientCertificate handle

	connectSendClientKeyXchg handle premasterRandom

	{- maybe send certificateVerify -}
	{- FIXME not implemented yet -}

	sendPacket handle (ChangeCipherSpec)
	lift $ hFlush handle

	{- send Finished -}
	connectSendFinish handle
	
	{- receive changeCipherSpec -}
	pktCCS <- recvPacket handle
	case pktCCS of
		Right ChangeCipherSpec -> return ()
		x                      -> error ("unexpected reply. expecting change cipher spec  " ++ show x)

	{- receive Finished -}
	pktFin <- recvPacket handle
	case pktFin of
		Right (Handshake (Finished _)) -> return ()
		x                              -> error ("unexpected reply. expecting finished " ++ show x)

	return ()

{- | sendData sends a bunch of data -}
sendData :: Handle -> L.ByteString -> TLSClient IO ()
sendData handle d = do
	if L.length d > 16384
		then do
			let (sending, remain) = L.splitAt 16384 d
			sendPacket handle $ AppData sending
			sendData handle remain
		else
			sendPacket handle $ AppData d

{- | recvData get data out of Data packet, and automatically try to renegociate if
 - a Handshake HelloRequest is received -}
recvData :: Handle -> TLSClient IO L.ByteString
recvData handle = do
	pkt <- recvPacket handle
	case pkt of
		Right (AppData x) -> return x
		Right (Handshake HelloRequest) -> do
			-- SECURITY FIXME audit the rng here..
			st <- getTLSState
			let (bytes, rng') = getRandomBytes (stRandomGen st) 32
			let (premaster, rng'') = getRandomBytes rng' 46
			putTLSState $ st { stRandomGen = rng'' }
			let crand = fromJust $ clientRandom bytes
			connect handle crand (ClientKeyData premaster)
			recvData handle
		Left err          -> error ("error received: " ++ show err)
		_                 -> error "unexpected item"

{- | close a TLS connection.
 - note that it doesn't close the handle, but just signal we're going to close
 - the connection to the other side -}
close :: Handle -> TLSClient IO ()
close handle = do
	sendPacket handle $ Alert (AlertLevel_Warning, CloseNotify)
