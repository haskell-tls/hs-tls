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

import Data.Maybe (isJust)
import Control.Applicative ((<$>))
import Control.Monad.State
import Control.Monad.Error

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Network.TLS.Util
import Network.TLS.Cap
import Network.TLS.Struct
import Network.TLS.Packet
import Network.TLS.State
import Network.TLS.Cipher
import Network.TLS.Crypto
import Data.Certificate.X509

import qualified Crypto.Cipher.RSA as RSA

returnEither :: Either TLSError a -> TLSSt a
returnEither (Left err) = throwError err
returnEither (Right a)  = return a

readPacket :: Header -> EncryptedData -> TLSSt [Packet]
readPacket hdr content = checkState hdr >> decryptContent hdr content >>= processPacket hdr

checkState :: Header -> TLSSt ()
checkState (Header pt _ _) =
		stStatus <$> get >>= \status -> unless (allowed pt status) $ throwError $ Error_Packet_unexpected (show status) (show pt)
	where
		allowed :: ProtocolType -> TLSStatus -> Bool
		allowed ProtocolType_Alert _                    = True
		allowed ProtocolType_Handshake _                = True
		allowed ProtocolType_AppData StatusHandshakeReq = True
		allowed ProtocolType_AppData StatusOk           = True
		allowed ProtocolType_ChangeCipherSpec (StatusHandshake HsStatusClientFinished) = True
		allowed ProtocolType_ChangeCipherSpec (StatusHandshake HsStatusClientKeyXchg) = True
		allowed ProtocolType_ChangeCipherSpec (StatusHandshake HsStatusClientCertificateVerify) = True
		allowed _ _ = False

processPacket :: Header -> Bytes -> TLSSt [Packet]

processPacket (Header ProtocolType_AppData _ _) content = return [AppData content]

processPacket (Header ProtocolType_Alert _ _) content = return . (:[]) . Alert =<< returnEither (decodeAlert content)

processPacket (Header ProtocolType_ChangeCipherSpec _ _) content = do
	e <- updateStatusCC False
	when (isJust e) $ throwError (fromJust "" e)

	returnEither $ decodeChangeCipherSpec content
	switchRxEncryption
	isClientContext >>= \cc -> when (not cc) setKeyBlock
	return [ChangeCipherSpec]

processPacket (Header ProtocolType_Handshake ver _) dcontent = do
	handshakes <- returnEither (decodeHandshakes dcontent)
	forM handshakes $ \(ty, content) -> do
		hs <- processHandshake ver ty content
		when (finishHandshakeTypeMaterial ty) $ updateHandshakeDigestSplitted ty content
		return hs

processHandshake :: Version -> HandshakeType -> ByteString -> TLSSt Packet
processHandshake ver ty econtent = do
	-- SECURITY FIXME if RSA fail, we need to generate a random master secret and not fail.
	e <- updateStatusHs ty
	when (isJust e) $ throwError (fromJust "" e)

	keyxchg <- getCipherKeyExchangeType
	let currentparams = CurrentParams
		{ cParamsVersion     = ver
		, cParamsKeyXchgType = maybe CipherKeyExchange_RSA id $ keyxchg
		}
	content <- case ty of
		HandshakeType_ClientKeyXchg -> either (const econtent) id <$> decryptRSA econtent
		_                           -> return econtent
	hs <- case (ty, decodeHandshake currentparams ty content) of
		(_, Right x)                          -> return x
		(HandshakeType_ClientKeyXchg, Left _) -> return $ ClientKeyXchg SSL2 (ClientKeyData $ B.replicate 46 0xff)
		(_, Left err)                         -> throwError err
	clientmode <- isClientContext
	case hs of
		ClientHello cver ran _ _ _ _ -> unless clientmode $ do
			startHandshakeClient cver ran
		ServerHello sver ran _ _ _ _ -> when clientmode $ do
			setServerRandom ran
			setVersion sver
		Certificates certs           -> when clientmode $ do processCertificates certs
		ClientKeyXchg cver _         -> unless clientmode $ do
			processClientKeyXchg cver content
		Finished fdata               -> processClientFinished fdata
		_                            -> return ()
	return $ Handshake hs

decryptRSA :: ByteString -> TLSSt (Either KxError ByteString)
decryptRSA econtent = do
	ver <- stVersion <$> get
	rsapriv <- fromJust "rsa private key" . hstRSAPrivateKey . fromJust "handshake" . stHandshake <$> get
	return $ kxDecrypt rsapriv (if ver < TLS10 then econtent else B.drop 2 econtent)

-- process the client key exchange message. the protocol expects the initial
-- client version received in ClientHello, not the negociated version.
-- in case the version mismatch, generate a random master secret
processClientKeyXchg :: Version -> ByteString -> TLSSt ()
processClientKeyXchg ver content = do
	expectedVer <- hstClientVersion . fromJust "handshake" . stHandshake <$> get
	setMasterSecret =<<
		if expectedVer /= ver
		then genTLSRandom (fromIntegral $ B.length content)
		else return content

processClientFinished :: FinishedData -> TLSSt ()
processClientFinished fdata = do
	cc <- stClientContext <$> get
	expected <- getHandshakeDigest (not cc)
	when (expected /= B.pack fdata) $ do
		-- FIXME don't fail, but report the error so that the code can send a BadMac Alert.
		fail ("client mac failure: expecting " ++ show expected ++ " received " ++ (show $L.pack fdata))
	return ()

decryptContent :: Header -> EncryptedData -> TLSSt ByteString
decryptContent hdr e@(EncryptedData b) = do
	st <- get
	if stRxEncrypted st
		then decryptData e >>= getCipherData hdr
		else return b

getCipherData :: Header -> CipherData -> TLSSt ByteString
getCipherData hdr cdata = do
	-- check if the MAC is valid.
	macValid <- case cipherDataMAC cdata of
		Nothing     -> return True
		Just digest -> do
			let (Header pt ver _) = hdr
			let new_hdr = Header pt ver (fromIntegral $ B.length $ cipherDataContent cdata)
			expected_digest <- makeDigest False new_hdr $ cipherDataContent cdata
			if expected_digest == digest
				then return True
				else return False

	-- check if the padding is filled with the correct pattern if it exists
	paddingValid <- case cipherDataPadding cdata of
		Nothing  -> return True
		Just pad -> do
			ver <- stVersion <$> get
			let b = B.length pad - 1
			if ver < TLS10
				then return True
				else return $ maybe True (const False) $ B.find (/= fromIntegral b) pad

	unless (and $! [ macValid, paddingValid ]) $ do
		throwError $ Error_Digest ([], [])

	return $ cipherDataContent cdata

decryptData :: EncryptedData -> TLSSt CipherData
decryptData (EncryptedData econtent) = do
	st <- get

	let cipher       = fromJust "cipher" $ stCipher st
	let cst          = fromJust "rx crypt state" $ stRxCryptState st
	let padding_size = fromIntegral $ cipherPaddingSize cipher
	let digestSize   = fromIntegral $ cipherDigestSize cipher
	let writekey     = cstKey cst

	case cipherF cipher of
		CipherNoneF -> do
			let contentlen = B.length econtent - digestSize
			case partition3 econtent (contentlen, digestSize, 0) of
				Nothing                ->
					throwError $ Error_Misc "partition3 failed"
				Just (content, mac, _) ->
					return $ CipherData
						{ cipherDataContent = content
						, cipherDataMAC     = Just mac
						, cipherDataPadding = Nothing
						}
		CipherBlockF _ decryptF -> do
			{- update IV -}
			let (iv, econtent') =
				if hasExplicitBlockIV $ stVersion st
					then B.splitAt (fromIntegral $ cipherIVSize cipher) econtent
					else (cstIV cst, econtent)
			let newiv = fromJust "new iv" $ takelast padding_size econtent'
			put $ st { stRxCryptState = Just $ cst { cstIV = newiv } }

			let content' = decryptF writekey iv econtent'
			let paddinglength = fromIntegral (B.last content') + 1
			let contentlen = B.length content' - paddinglength - digestSize
			let (content, mac, padding) = fromJust "p3" $ partition3 content' (contentlen, digestSize, paddinglength)
			return $ CipherData
				{ cipherDataContent = content
				, cipherDataMAC     = Just mac
				, cipherDataPadding = Just padding
				}
		CipherStreamF initF _ decryptF -> do
			let iv = cstIV cst
			let (content', newiv) = decryptF (if iv /= B.empty then iv else initF writekey) econtent
			{- update Ctx -}
			let contentlen        = B.length content' - digestSize
			let (content, mac, _) = fromJust "p3" $ partition3 content' (contentlen, digestSize, 0)
			put $ st { stRxCryptState = Just $ cst { cstIV = newiv } }
			return $ CipherData
				{ cipherDataContent = content
				, cipherDataMAC     = Just mac
				, cipherDataPadding = Nothing
				}

processCertificates :: [X509] -> TLSSt ()
processCertificates certs = do
	let (X509 mainCert _ _ _ _) = head certs
	case certPubKey mainCert of
		PubKeyRSA (lm, m, e) -> do
			let pk = PubRSA (RSA.PublicKey { RSA.public_sz = fromIntegral lm, RSA.public_n = m, RSA.public_e = e })
			setPublicKey pk
		_                    -> return ()
