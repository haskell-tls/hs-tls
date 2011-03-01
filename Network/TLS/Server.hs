{-# LANGUAGE GeneralizedNewtypeDeriving, MultiParamTypeClasses #-}
-- |
-- Module      : Network.TLS.Server
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Server module contains the necessary calls to create a listening TLS socket
-- aka. a server socket.
--

module Network.TLS.Server
	( TLSParams(..)
	, TLSStateServer
	, runTLSServer
	-- * low level packet sending receiving.
	, recvPacket
	, sendPacket
	-- * API, warning probably subject to change
	, listen
	, sendData
	, recvData
	, close
	) where

import Data.Maybe
import Data.List (intersect, find)
import Control.Monad.Trans
import Control.Monad.State
import Control.Applicative ((<$>))
import Network.TLS.Core
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

data TLSStateServer = TLSStateServer
	{ scParams   :: TLSParams -- ^ server params and config for this connection
	, scTLSState :: TLSState  -- ^ server TLS State for this connection
	}

newtype TLSServer m a = TLSServer { runTLSC :: StateT TLSStateServer m a }
	deriving (Monad, MonadState TLSStateServer)

instance MonadTrans TLSServer where
	lift = TLSServer . lift

instance (Monad m, Functor m) => Functor (TLSServer m) where
	fmap f = TLSServer . fmap f . runTLSC

runTLSServerST :: TLSServer m a -> TLSStateServer -> m (a, TLSStateServer)
runTLSServerST f s = runStateT (runTLSC f) s

runTLSServer :: TLSServer m a -> TLSParams -> SRandomGen -> m (a, TLSStateServer)
runTLSServer f params rng = runTLSServerST f (TLSStateServer { scParams = params, scTLSState = state })
	where state = (newTLSState rng) { stClientContext = False }

usingState :: Monad m => TLSSt a -> TLSServer m (Either TLSError a)
usingState f =
	get >>= return . scTLSState >>= execAndStore
	where
		execAndStore st = do
			let (a, newst) = runTLSState f st
			modify (\stateserver -> stateserver { scTLSState = newst })
			return a

usingState_ f = do
	ret <- usingState f
	case ret of
		Left err -> error "assertion failed, error in path without an error"
		Right r  -> return r

getStateRNG n = usingState_ (withTLSRNG (\rng -> getRandomBytes rng n))

{- | receive a single TLS packet or on error a TLSError -}
recvPacket :: Handle -> TLSServer IO (Either TLSError [Packet])
recvPacket handle = do
	hdr <- lift $ B.hGet handle 5 >>= return . decodeHeader
	case hdr of
		Left err -> return $ Left err
		Right header@(Header _ _ readlen) -> do
			content <- lift $ B.hGet handle (fromIntegral readlen)
			usingState $ readPacket header (EncryptedData content)

{- | send a single TLS packet -}
sendPacket :: Handle -> Packet -> TLSServer IO ()
sendPacket handle pkt = do
	dataToSend <- usingState_ $ writePacket pkt
	lift $ B.hPut handle dataToSend

handleClientHello :: Handshake -> TLSServer IO ()
handleClientHello (ClientHello ver _ _ ciphers compressionID _) = do
	cfg <- get >>= return . scParams
	when (not $ elem ver (pAllowedVersions cfg)) $ do
		{- unsupported version -}
		fail "unsupported version"

	let commonCiphers = intersect ciphers (map cipherID $ pCiphers cfg)
	when (commonCiphers == []) $ do
		{- unsupported cipher -}
		fail ("unsupported cipher: " ++ show ciphers ++ " : server : " ++ (show $ map cipherID $ pCiphers cfg))

	when (not $ elem 0 compressionID) $ do
		{- unsupported compression -}
		fail "unsupported compression"

	usingState_ $ modify (\st -> st
		{ stVersion = ver
		, stCipher = find (\c -> cipherID c == (head commonCiphers)) (pCiphers cfg)
		})

handleClientHello _ = do
	fail "unexpected handshake type received. expecting client hello"

handshakeSendServerData :: Handle -> TLSServer IO ()
handshakeSendServerData handle = do
	srand <- fromJust . serverRandom <$> getStateRNG 32
	sp <- get >>= return . scParams
	st <- get >>= return . scTLSState

	let cipher = fromJust $ stCipher st

	let srvhello = ServerHello (stVersion st) srand (Session Nothing) (cipherID cipher) 0 Nothing
	let srvCerts = Certificates $ map fst $ pCertificates sp
	case map snd $ pCertificates sp of
		(Just privkey : _) -> usingState_ $ setPrivateKey privkey
		_                  -> return () -- return a sensible error

	-- in TLS12, we need to check as well the certificates we are sending if they have in the extension
	-- the necessary bits set.
	let needkeyxchg = cipherExchangeNeedMoreData $ cipherKeyExchange cipher

	sendPacket handle (Handshake srvhello)
	sendPacket handle (Handshake srvCerts)
	when needkeyxchg $ do
		let skg = SKX_RSA Nothing
		sendPacket handle (Handshake $ ServerKeyXchg skg)
	-- FIXME we don't do this on a Anonymous server
	when (pWantClientCert sp) $ do
		let certTypes = [ CertificateType_RSA_Sign ]
		let creq = CertRequest certTypes Nothing [0,0,0]
		sendPacket handle (Handshake creq)
	sendPacket handle (Handshake ServerHelloDone)

handshakeSendFinish :: Handle -> TLSServer IO ()
handshakeSendFinish handle = do
	cf <- usingState_ $ getHandshakeDigest False
	sendPacket handle (Handshake $ Finished $ B.unpack cf)

{- after receiving a client hello, we need to redo a handshake -}
handshake :: Handle -> TLSServer IO ()
handshake handle = do
	handshakeSendServerData handle
	lift $ hFlush handle

	whileStatus (/= (StatusHandshake HsStatusClientFinished)) (recvPacket handle)

	sendPacket handle ChangeCipherSpec
	handshakeSendFinish handle

	lift $ hFlush handle

	return ()
	where
		whileStatus p a = do
			b <- usingState_ (p . stStatus <$> get)
			when b (a >> whileStatus p a)


{- | listen on a handle to a new TLS connection. -}
listen :: Handle -> TLSServer IO ()
listen handle = do
	pkts <- recvPacket handle
	case pkts of
		Right [Handshake hs] -> handleClientHello hs
		x                    -> fail ("unexpected type received. expecting handshake ++ " ++ show x)
	handshake handle

sendDataChunk :: Handle -> B.ByteString -> TLSServer IO ()
sendDataChunk handle d =
	if B.length d > 16384
		then do
			let (sending, remain) = B.splitAt 16384 d
			sendPacket handle $ AppData sending
			sendDataChunk handle remain
		else
			sendPacket handle $ AppData d

{- | sendData sends a bunch of data -}
sendData :: Handle -> L.ByteString -> TLSServer IO ()
sendData handle d = mapM_ (sendDataChunk handle) (L.toChunks d)

{- | recvData get data out of Data packet, and automatically renegociate if
 - a Handshake ClientHello is received -}
recvData :: Handle -> TLSServer IO L.ByteString
recvData handle = do
	pkt <- recvPacket handle
	case pkt of
		Right [Handshake (ClientHello _ _ _ _ _ _)] -> handshake handle >> recvData handle
		Right [AppData x] -> return $ L.fromChunks [x]
		Left err          -> error ("error received: " ++ show err)
		_                 -> error "unexpected item"

{- | close a TLS connection.
 - note that it doesn't close the handle, but just signal we're going to close
 - the connection to the other side -}
close :: Handle -> TLSServer IO ()
close handle = do
	sendPacket handle $ Alert (AlertLevel_Warning, CloseNotify)
