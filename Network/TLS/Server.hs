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
	( listen
	, recvData
	) where

import Data.Maybe
import Data.List (intersect, find)
import Control.Monad.Trans
import Control.Monad.State
import Control.Applicative ((<$>))
import Network.TLS.Core
import Network.TLS.Cipher
import Network.TLS.Struct
import Network.TLS.State
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import System.IO (hFlush)

handleClientHello :: MonadIO m => TLSCtx -> Handshake -> m ()
handleClientHello ctx (ClientHello ver _ _ ciphers compressionID _) = do
	let cfg = getParams ctx
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

	usingState_ ctx $ modify (\st -> st
		{ stVersion = ver
		, stCipher = find (\c -> cipherID c == (head commonCiphers)) (pCiphers cfg)
		})

handleClientHello _ _ = do
	fail "unexpected handshake type received. expecting client hello"

handshakeSendServerData :: MonadIO m => TLSCtx -> m ()
handshakeSendServerData ctx = do
	srand <- getStateRNG ctx 32 >>= return . ServerRandom
	let sp = getParams ctx
	--st    <- get >>= return . scTLSState

	cipher <- usingState_ ctx (fromJust . stCipher <$> get)
	ver    <- usingState_ ctx (stVersion <$> get)

	let srvhello = ServerHello ver srand (Session Nothing) (cipherID cipher) 0 Nothing
	let srvCerts = Certificates $ map fst $ pCertificates sp
	case map snd $ pCertificates sp of
		(Just privkey : _) -> usingState_ ctx $ setPrivateKey privkey
		_                  -> return () -- return a sensible error

	-- in TLS12, we need to check as well the certificates we are sending if they have in the extension
	-- the necessary bits set.
	let needkeyxchg = cipherExchangeNeedMoreData $ cipherKeyExchange cipher

	sendPacket ctx (Handshake srvhello)
	sendPacket ctx (Handshake srvCerts)
	when needkeyxchg $ do
		let skg = SKX_RSA Nothing
		sendPacket ctx (Handshake $ ServerKeyXchg skg)
	-- FIXME we don't do this on a Anonymous server
	when (pWantClientCert sp) $ do
		let certTypes = [ CertificateType_RSA_Sign ]
		let creq = CertRequest certTypes Nothing [0,0,0]
		sendPacket ctx (Handshake creq)
	sendPacket ctx (Handshake ServerHelloDone)

handshakeSendFinish :: MonadIO m => TLSCtx -> m ()
handshakeSendFinish ctx = do
	cf <- usingState_ ctx $ getHandshakeDigest False
	sendPacket ctx (Handshake $ Finished $ B.unpack cf)

{- after receiving a client hello, we need to redo a handshake -}
handshakeServer :: MonadIO m => TLSCtx -> m ()
handshakeServer ctx = do
	handshakeSendServerData ctx
	liftIO $ hFlush $ getHandle ctx

	whileStatus ctx (/= (StatusHandshake HsStatusClientFinished)) (recvPacket ctx)

	sendPacket ctx ChangeCipherSpec
	handshakeSendFinish ctx

	liftIO $ hFlush $ getHandle ctx

	return ()

{- | listen on a handle to a new TLS connection. -}
listen :: MonadIO m => TLSCtx -> m ()
listen ctx = do
	pkts <- recvPacket ctx
	case pkts of
		Right [Handshake hs] -> handleClientHello ctx hs
		x                    -> fail ("unexpected type received. expecting handshake ++ " ++ show x)
	handshakeServer ctx

{- | recvData get data out of Data packet, and automatically renegociate if
 - a Handshake ClientHello is received -}
recvData :: MonadIO m => TLSCtx -> m L.ByteString
recvData ctx = do
	pkt <- recvPacket ctx
	case pkt of
		Right [Handshake (ClientHello _ _ _ _ _ _)] -> handshake ctx >> recvData ctx
		Right [AppData x] -> return $ L.fromChunks [x]
		Left err          -> error ("error received: " ++ show err)
		_                 -> error "unexpected item"
