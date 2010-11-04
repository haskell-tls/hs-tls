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
	( TLSServerParams(..)
	, TLSServerCallbacks(..)
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

import Data.Word
import Data.Maybe
import Data.List (intersect, find)
import Control.Monad.Trans
import Control.Monad.State
import Control.Applicative ((<$>))
import Data.Certificate.X509
import qualified Data.Certificate.Key as CertificateKey
import Network.TLS.Cipher
import Network.TLS.Crypto
import Network.TLS.Struct
import Network.TLS.Packet
import Network.TLS.State
import Network.TLS.Sending
import Network.TLS.Receiving
import Network.TLS.SRandom
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import System.IO (Handle, hFlush)
import qualified Crypto.Cipher.RSA as RSA

type TLSServerCert = (B.ByteString, Certificate, CertificateKey.PrivateKey)

data TLSServerCallbacks = TLSServerCallbacks
	{ cbCertificates :: Maybe ([Certificate] -> IO Bool) -- ^ optional callback to verify certificates
	}

instance Show TLSServerCallbacks where
	show _ = "[callbacks]"

data TLSServerParams = TLSServerParams
	{ spAllowedVersions :: [Version]           -- ^ allowed versions that we can use
	, spSessions        :: [[Word8]]           -- ^ placeholder for futur known sessions
	, spCiphers         :: [Cipher]            -- ^ all ciphers that the server side support
	, spCertificate     :: Maybe TLSServerCert -- ^ the certificate we serve to the client
	, spWantClientCert  :: Bool                -- ^ configure if we do a cert request to the client
	, spCallbacks       :: TLSServerCallbacks  -- ^ user callbacks
	}

data TLSStateServer = TLSStateServer
	{ scParams   :: TLSServerParams -- ^ server params and config for this connection
	, scTLSState :: TLSState        -- ^ server TLS State for this connection
	}

newtype TLSServer m a = TLSServer { runTLSC :: StateT TLSStateServer m a }
	deriving (Monad, MonadState TLSStateServer)

instance Monad m => MonadTLSState (TLSServer m) where
	getTLSState   = TLSServer (get >>= return . scTLSState)
	putTLSState s = TLSServer (get >>= put . (\st -> st { scTLSState = s }))

instance MonadTrans TLSServer where
	lift = TLSServer . lift

instance (Monad m, Functor m) => Functor (TLSServer m) where
	fmap f = TLSServer . fmap f . runTLSC

runTLSServerST :: TLSServer m a -> TLSStateServer -> m (a, TLSStateServer)
runTLSServerST f s = runStateT (runTLSC f) s

runTLSServer :: TLSServer m a -> TLSServerParams -> SRandomGen -> m (a, TLSStateServer)
runTLSServer f params rng = runTLSServerST f (TLSStateServer { scParams = params, scTLSState = state })
	where state = (newTLSState rng) { stClientContext = False }

{- | receive a single TLS packet or on error a TLSError -}
recvPacket :: Handle -> TLSServer IO (Either TLSError [Packet])
recvPacket handle = do
	hdr <- lift $ B.hGet handle 5 >>= return . decodeHeader
	case hdr of
		Left err -> return $ Left err
		Right header@(Header _ _ readlen) -> do
			content <- lift $ B.hGet handle (fromIntegral readlen)
			readPacket header (EncryptedData content)

{- | send a single TLS packet -}
sendPacket :: Handle -> Packet -> TLSServer IO ()
sendPacket handle pkt = do
	dataToSend <- writePacket pkt
	lift $ B.hPut handle dataToSend

handleClientHello :: Handshake -> TLSServer IO ()
handleClientHello (ClientHello ver _ _ ciphers compressionID _) = do
	cfg <- get >>= return . scParams
	when (not $ elem ver (spAllowedVersions cfg)) $ do
		{- unsupported version -}
		fail "unsupported version"

	let commonCiphers = intersect ciphers (map cipherID $ spCiphers cfg)
	when (commonCiphers == []) $ do
		{- unsupported cipher -}
		fail ("unsupported cipher: " ++ show ciphers ++ " : server : " ++ (show $ map cipherID $ spCiphers cfg))

	when (not $ elem 0 compressionID) $ do
		{- unsupported compression -}
		fail "unsupported compression"

	modifyTLSState (\st -> st
		{ stVersion = ver
		, stCipher = find (\c -> cipherID c == (head commonCiphers)) (spCiphers cfg)
		})

handleClientHello _ = do
	fail "unexpected handshake type received. expecting client hello"

handshakeSendServerData :: Handle -> TLSServer IO ()
handshakeSendServerData handle = do
	srand <- fromJust . serverRandom <$> withTLSRNG (\rng -> getRandomBytes rng 32)
	sp <- get >>= return . scParams
	st <- getTLSState

	let cipher = fromJust $ stCipher st

	let srvhello = ServerHello (stVersion st) srand (Session Nothing) (cipherID cipher) 0 Nothing
	let (_,cert,privkeycert) = fromJust $ spCertificate sp
	let srvcert = Certificates [ cert ]


	-- in TLS12, we need to check as well the certificates we are sending if they have in the extension
	-- the necessary bits set.
	let needkeyxchg = cipherExchangeNeedMoreData $ cipherKeyExchange cipher

	let privkey = PrivRSA $ RSA.PrivateKey
		{ RSA.private_sz   = fromIntegral $ CertificateKey.privKey_lenmodulus privkeycert
		, RSA.private_n    = CertificateKey.privKey_modulus privkeycert
		, RSA.private_d    = CertificateKey.privKey_private_exponant privkeycert
		, RSA.private_p    = CertificateKey.privKey_p1 privkeycert
		, RSA.private_q    = CertificateKey.privKey_p2 privkeycert
		, RSA.private_dP   = CertificateKey.privKey_exp1 privkeycert
		, RSA.private_dQ   = CertificateKey.privKey_exp2 privkeycert
		, RSA.private_qinv = CertificateKey.privKey_coef privkeycert
		}
	setPrivateKey privkey

	sendPacket handle (Handshake srvhello)
	sendPacket handle (Handshake srvcert)
	when needkeyxchg $ do
		let skg = SKX_RSA Nothing
		sendPacket handle (Handshake $ ServerKeyXchg skg)
	-- FIXME we don't do this on a Anonymous server
	when (spWantClientCert sp) $ do
		let certTypes = [ CertificateType_RSA_Sign ]
		let creq = CertRequest certTypes Nothing [0,0,0]
		sendPacket handle (Handshake creq)
	sendPacket handle (Handshake ServerHelloDone)

handshakeSendFinish :: Handle -> TLSServer IO ()
handshakeSendFinish handle = do
	cf <- getHandshakeDigest False
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
