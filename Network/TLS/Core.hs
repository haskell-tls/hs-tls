-- |
-- Module      : Network.TLS.Core
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Core
	(
	-- ^ Context configuration
	  TLSParams(..)
	, defaultParams
	-- ^ Context object
	, TLSCtx
	, getParams
	, getHandle
	-- hide
	, usingState
	, usingState_
	, getStateRNG
	, whileStatus
	-- api
	, sendPacket
	, recvPacket
	, client
	, server
	, bye
	, handshake
	, sendData
	, recvData
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
import Data.Maybe
import Data.Certificate.X509
import Data.List (intersect, intercalate, find)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Control.Applicative ((<$>))
import Control.Concurrent.MVar
import Control.Monad.State
import System.IO (Handle, hSetBuffering, BufferMode(..), hFlush)

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
		Left err -> error ("assertion failed, wrong use of state_: " ++ show err)
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

client :: MonadIO m => TLSParams -> SRandomGen -> Handle -> m TLSCtx
client params rng handle = liftIO $ newCtx handle params state
	where state = (newTLSState rng) { stClientContext = True }

server :: MonadIO m => TLSParams -> SRandomGen -> Handle -> m TLSCtx
server params rng handle = liftIO $ newCtx handle params state
	where state = (newTLSState rng) { stClientContext = False }

getParams :: TLSCtx -> TLSParams
getParams = ctxParams

getHandle :: TLSCtx -> Handle
getHandle = ctxHandle

{- | close a TLS connection.
 - note that it doesn't close the handle, but just signal we're going to close
 - the connection to the other side -}
bye :: MonadIO m => TLSCtx -> m ()
bye ctx = sendPacket ctx $ Alert (AlertLevel_Warning, CloseNotify)

{- | handshake a new TLS connection through a handshake on a handle. -}
handshakeClient :: MonadIO m => TLSCtx -> m ()
handshakeClient ctx = do
	-- Send ClientHello
	crand <- getStateRNG ctx 32 >>= return . ClientRandom
	sendPacket ctx $ Handshake $ ClientHello ver crand
	                                         (Session Nothing)
	                                         (map cipherID ciphers)
	                                         (map compressionID compressions)
	                                         Nothing

	-- Receive Server information until ServerHelloDone
	whileStatus ctx (/= (StatusHandshake HsStatusServerHelloDone)) $ do
		pkts <- recvPacket ctx
		case pkts of
			Left err -> error ("error received: " ++ show err)
			Right l  -> mapM_ processServerInfo l

	-- Send Certificate if requested. XXX disabled for now.
	certRequested <- return False
	when certRequested (sendPacket ctx $ Handshake (Certificates clientCerts))

	-- Send ClientKeyXchg
	prerand <- getStateRNG ctx 46 >>= return . ClientKeyData
	sendPacket ctx $ Handshake (ClientKeyXchg ver prerand)

	{- maybe send certificateVerify -}
	{- FIXME not implemented yet -}

	sendPacket ctx ChangeCipherSpec
	liftIO $ hFlush $ getHandle ctx

	-- Send Finished
	cf <- usingState_ ctx $ getHandshakeDigest True
	sendPacket ctx (Handshake $ Finished $ B.unpack cf)

	-- receive changeCipherSpec & Finished
	recvPacket ctx >> recvPacket ctx >> return ()

	where
		params       = getParams ctx
		ver          = pConnectVersion params
		allowedvers  = pAllowedVersions params
		ciphers      = pCiphers params
		compressions = pCompressions params
		clientCerts  = map fst $ pCertificates params

		processServerInfo (Handshake (ServerHello rver _ _ cipher _ _)) = do
			case find ((==) rver) allowedvers of
				Nothing -> error ("received version which is not allowed: " ++ show ver)
				Just _  -> usingState_ ctx $ setVersion ver
			case find ((==) cipher . cipherID) ciphers of
				Nothing -> error "no cipher in common with the server"
				Just c  -> usingState_ ctx $ setCipher c

		processServerInfo (Handshake (CertRequest _ _ _)) = do
			return ()
			--modify (\sc -> sc { scCertRequested = True })

		processServerInfo (Handshake (Certificates certs)) = do
			let cb = onCertificatesRecv $ getParams ctx
			valid <- liftIO $ cb certs
			unless valid $ error "certificates received deemed invalid by user"

		processServerInfo _ = return ()

handshakeServerWith :: MonadIO m => TLSCtx -> Handshake -> m ()
handshakeServerWith ctx (ClientHello ver _ _ ciphers compressions _) = do
	-- Handle Client hello
	when (not $ elem ver (pAllowedVersions params)) $ fail "unsupported version"
	when (commonCiphers == []) $ fail "no common cipher supported"
	when (commonCompressions == []) $ fail "no common compression supported"
	usingState_ ctx $ modify (\st -> st
		{ stVersion = ver
		, stCipher  = Just usedCipher
		--, stCompression = Just usedCompression
		})

	-- send Server Data until ServerHelloDone
	handshakeSendServerData
	liftIO $ hFlush $ getHandle ctx

	-- Receive client info until client Finished.
	whileStatus ctx (/= (StatusHandshake HsStatusClientFinished)) (recvPacket ctx)

	sendPacket ctx ChangeCipherSpec

	-- Send Finish
	cf <- usingState_ ctx $ getHandshakeDigest False
	sendPacket ctx (Handshake $ Finished $ B.unpack cf)

	liftIO $ hFlush $ getHandle ctx
	return ()
	where
		params             = getParams ctx
		commonCiphers      = intersect ciphers (map cipherID $ pCiphers params)
		usedCipher         = fromJust $ find (\c -> cipherID c == head commonCiphers) (pCiphers params)
		commonCompressions = intersect compressions (map compressionID $ pCompressions params)
		usedCompression    = fromJust $ find (\c -> compressionID c == head commonCompressions) (pCompressions params)
		srvCerts           = map fst $ pCertificates params
		privKeys           = map snd $ pCertificates params
		needKeyXchg        = cipherExchangeNeedMoreData $ cipherKeyExchange usedCipher

		handshakeSendServerData = do
			srand <- getStateRNG ctx 32 >>= return . ServerRandom

			case privKeys of
				(Just privkey : _) -> usingState_ ctx $ setPrivateKey privkey
				_                  -> return () -- return a sensible error

			-- in TLS12, we need to check as well the certificates we are sending if they have in the extension
			-- the necessary bits set.

			-- send ServerHello & Certificate & ServerKeyXchg & CertReq
			sendPacket ctx $ Handshake $ ServerHello ver srand
			                                         (Session Nothing)
			                                         (cipherID usedCipher)
			                                         (compressionID usedCompression)
			                                         Nothing
			sendPacket ctx (Handshake $ Certificates srvCerts)
			when needKeyXchg $ do
				let skg = SKX_RSA Nothing
				sendPacket ctx (Handshake $ ServerKeyXchg skg)
			-- FIXME we don't do this on a Anonymous server
			when (pWantClientCert params) $ do
				let certTypes = [ CertificateType_RSA_Sign ]
				let creq = CertRequest certTypes Nothing [0,0,0]
				sendPacket ctx (Handshake creq)
			-- Send HelloDone
			sendPacket ctx (Handshake ServerHelloDone)

handshakeServerWith _ _ = do
	fail "unexpected handshake type received. expecting client hello"

{- after receiving a client hello, we need to redo a handshake -}
handshakeServer :: MonadIO m => TLSCtx -> m ()
handshakeServer ctx = do
	pkts <- recvPacket ctx
	case pkts of
		Right [Handshake hs] -> handshakeServerWith ctx hs
		x                    -> fail ("unexpected type received. expecting handshake ++ " ++ show x)

{-| Handshake for a new TLS connection
 - This is to be called at the beGinning of a connection, and during renegociation -}
handshake :: MonadIO m => TLSCtx -> m ()
handshake ctx = do
	cc <- usingState_ ctx (stClientContext <$> get)
	if cc
		then handshakeClient ctx
		else handshakeServer ctx

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
recvData ctx = do
	pkt <- recvPacket ctx
	case pkt of
		-- on server context receiving a client hello == renegociation
		Right [Handshake ch@(ClientHello _ _ _ _ _ _)] ->
			handshakeServerWith ctx ch >> recvData ctx
		-- on client context, receiving a hello request == renegociation
		Right [Handshake HelloRequest] ->
			handshakeClient ctx >> recvData ctx
		Right [AppData x] -> return $ L.fromChunks [x]
		Left err          -> error ("error received: " ++ show err)
		_                 -> error "unexpected item"
