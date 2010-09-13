{-# LANGUAGE GeneralizedNewtypeDeriving, FlexibleContexts #-}

-- |
-- Module      : Network.TLS.Receiving
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Receiving module contains calls related to unmarshalling packets according
-- to the TLS state
--
module Network.TLS.Receiving (
	readPacket
	) where

import Control.Monad.State
import Control.Monad.Error
import Data.Maybe

import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as B

import Network.TLS.Struct
import Network.TLS.Packet
import Network.TLS.State
import Network.TLS.Cipher
import Network.TLS.Crypto
import Network.TLS.SRandom
import Data.Certificate.X509

newtype TLSRead a = TLSR { runTLSR :: ErrorT TLSError (State TLSState) a }
	deriving (Monad, MonadError TLSError)

instance Functor TLSRead where
	fmap f = TLSR . fmap f . runTLSR

instance MonadTLSState TLSRead where
	putTLSState x = TLSR (lift $ put x)
	getTLSState   = TLSR (lift get)

runTLSRead :: MonadTLSState m => TLSRead a -> m (Either TLSError a)
runTLSRead f = do
	st <- getTLSState
	let (a, newst) = runState (runErrorT (runTLSR f)) st
	putTLSState newst
	return a

returnEither :: Either TLSError a -> TLSRead a
returnEither (Left err) = throwError err
returnEither (Right a)  = return a

readPacket :: MonadTLSState m => Header -> EncryptedData -> m (Either TLSError Packet)
readPacket hdr@(Header ProtocolType_AppData _ _) content =
	runTLSRead (fmap AppData $ decryptContent hdr content)

readPacket hdr@(Header ProtocolType_Alert _ _)   content =
	runTLSRead (decryptContent hdr content >>= returnEither . decodeAlert >>= return . Alert)

readPacket hdr@(Header ProtocolType_ChangeCipherSpec _ _) content = runTLSRead $ do
	dcontent <- decryptContent hdr content
	returnEither $ decodeChangeCipherSpec dcontent
	switchRxEncryption
	isClientContext >>= \cc -> when (not cc) setKeyBlock
	return ChangeCipherSpec

readPacket hdr@(Header ProtocolType_Handshake ver _) content =
	runTLSRead (decryptContent hdr content >>= processHsPacket ver)

decryptRSA :: MonadTLSState m => ByteString -> m (Maybe ByteString)
decryptRSA econtent = do
	rsapriv <- getTLSState >>= return . fromJust . hstRSAPrivateKey . fromJust . stHandshake
	return $ rsaDecrypt rsapriv (L.drop 2 econtent)

setMasterSecretRandom :: ByteString -> TLSRead ()
setMasterSecretRandom content = do
	st <- getTLSState
	let (bytes, g') = getRandomBytes (stRandomGen st) (fromIntegral $ L.length content)
	putTLSState $ st { stRandomGen = g' }
	setMasterSecret (L.pack bytes)

processClientKeyXchg :: Version -> ByteString -> TLSRead ()
processClientKeyXchg ver content = do
	{- the TLS protocol expect the initial client version received in the ClientHello, not the negociated version -}
	expectedVer <- getTLSState >>= return . hstClientVersion . fromJust . stHandshake
	if expectedVer /= ver
		then setMasterSecretRandom content
		else setMasterSecret content

processClientFinished :: FinishedData -> TLSRead ()
processClientFinished fdata = do
	cc <- getTLSState >>= return . stClientContext
	expected <- getHandshakeDigest (not cc)
	when (expected /= L.pack fdata) $ do
		-- FIXME don't fail, but report the error so that the code can send a BadMac Alert.
		fail ("client mac failure: expecting " ++ show expected ++ " received " ++ (show $L.pack fdata))
	return ()

processHsPacket :: Version -> ByteString -> TLSRead Packet
processHsPacket ver dcontent = do
	(ty, econtent) <- returnEither $ decodeHandshakeHeader dcontent
	-- SECURITY FIXME if RSA fail, we need to generate a random master secret and not fail.
	content <- case ty of
		HandshakeType_ClientKeyXchg -> do
			copt <- decryptRSA econtent
			return $ maybe econtent id copt
		_                           ->
			return econtent
	hs <- case (ty, decodeHandshake ver ty content) of
		(_, Right x)                            -> return x
		(HandshakeType_ClientKeyXchg, Left _)   -> return $ ClientKeyXchg SSL2 (ClientKeyData $ replicate 0xff 46)
		(_, Left err)                           -> throwError err
	clientmode <- isClientContext
	case hs of
		ClientHello cver ran _ _ _ _ -> unless clientmode $ do
			startHandshakeClient cver ran
		ServerHello sver ran _ _ _ _ -> when clientmode $ do
			setServerRandom ran
			setVersion sver
		Certificates [cert]          -> when clientmode $ do processCertificate cert
		ClientKeyXchg cver _         -> unless clientmode $ do
			processClientKeyXchg cver content
		Finished fdata               -> processClientFinished fdata
		_                            -> return ()
	when (finishHandshakeTypeMaterial ty) (updateHandshakeDigest dcontent)
	return $ Handshake hs

decryptContentReally :: Header -> EncryptedData -> TLSRead ByteString
decryptContentReally hdr e = do
	st <- getTLSState
	unencrypted_content <- decryptData e
	let digestSize = cipherDigestSize $ fromJust $ stCipher st
	let (unencrypted_msg, digest) = L.splitAt (L.length unencrypted_content - fromIntegral digestSize) unencrypted_content
	let (Header pt ver _) = hdr
	let new_hdr = Header pt ver (fromIntegral $ L.length unencrypted_msg)
	expected_digest <- makeDigest False new_hdr unencrypted_msg

	if expected_digest == digest
		then return $ unencrypted_msg
		else throwError $ Error_Digest (L.unpack expected_digest, L.unpack digest)

decryptContent :: Header -> EncryptedData -> TLSRead ByteString
decryptContent hdr e@(EncryptedData b) = do
	st <- getTLSState
	if stRxEncrypted st
		then decryptContentReally hdr e
		else return b

takelast :: Int -> [a] -> [a]
takelast i b = drop (length b - i) b

decryptData :: EncryptedData -> TLSRead ByteString
decryptData (EncryptedData econtent) = do
	st <- getTLSState

	assert "decrypt data"
		[ ("cipher", isNothing $ stCipher st)
		, ("crypt state", isNothing $ stRxCryptState st) ]

	let cipher = fromJust $ stCipher st
	let cst = fromJust $ stRxCryptState st
	let padding_size = fromIntegral $ cipherPaddingSize cipher

	let writekey = B.pack $ cstKey cst
	let iv = B.pack $ cstIV cst

	contentpadded <- case cipherF cipher of
		CipherNoneF -> fail "none decrypt"
		CipherBlockF _ decryptF -> do
			{- update IV -}
			let newiv = takelast padding_size $ L.unpack econtent
			putTLSState $ st { stRxCryptState = Just $ cst { cstIV = newiv } }
			return $ decryptF writekey iv econtent
		CipherStreamF initF _ decryptF -> do
			let (content, newiv) = decryptF (if iv /= B.empty then iv else initF writekey) econtent
			{- update Ctx -}
			putTLSState $ st { stRxCryptState = Just $ cst { cstIV = B.unpack newiv } }
			return $ content
	let content =
		if cipherPaddingSize cipher > 0
			then
				let pb = L.last contentpadded + 1 in
				fst $ L.splitAt ((L.length contentpadded) - fromIntegral pb) contentpadded
			else contentpadded
	return content

processCertificate :: Certificate -> TLSRead ()
processCertificate cert = do
	case certPubKey cert of
		PubKey _ (PubKeyRSA (lm, m, e)) -> do
			let pk = PublicKey { public_size = fromIntegral lm, public_n = m, public_e = e }
			setPublicKey pk
		_                    -> return ()
