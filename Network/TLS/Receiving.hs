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
import Network.TLS.Record
import Network.TLS.Packet
import Network.TLS.State
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Crypto
import Data.Certificate.X509

returnEither :: Either TLSError a -> TLSSt a
returnEither (Left err) = throwError err
returnEither (Right a)  = return a

readPacket :: Record Ciphertext -> TLSSt Packet
readPacket record = checkState record >> decryptContent record >>= uncompressContent >>= processPacket

checkState :: Record a -> TLSSt ()
checkState (Record pt _ _) =
		stStatus <$> get >>= \status -> unless (allowed pt status) $ throwError (err status)
	where
		err st = Error_Protocol ("unexpected message received: status=" ++ show st, True, UnexpectedMessage)

		allowed :: ProtocolType -> TLSStatus -> Bool
		allowed ProtocolType_Alert _                    = True
		allowed ProtocolType_Handshake _                = True
		allowed ProtocolType_AppData StatusHandshakeReq = True
		allowed ProtocolType_AppData StatusOk           = True
		allowed ProtocolType_ChangeCipherSpec (StatusHandshake HsStatusClientFinished) = True
		allowed ProtocolType_ChangeCipherSpec (StatusHandshake HsStatusClientKeyXchg) = True
		allowed ProtocolType_ChangeCipherSpec (StatusHandshake HsStatusClientCertificateVerify) = True
		allowed _ _ = False

processPacket :: Record Plaintext -> TLSSt Packet

processPacket (Record ProtocolType_AppData _ fragment) = return $ AppData $ fragmentGetBytes fragment

processPacket (Record ProtocolType_Alert _ fragment) = return . Alert =<< returnEither (decodeAlerts $ fragmentGetBytes fragment)

processPacket (Record ProtocolType_ChangeCipherSpec _ fragment) = do
	e <- updateStatusCC False
	when (isJust e) $ throwError (fromJust "" e)

	returnEither $ decodeChangeCipherSpec $ fragmentGetBytes fragment
	switchRxEncryption
	isClientContext >>= \cc -> when (not cc) setKeyBlock
	return ChangeCipherSpec

processPacket (Record ProtocolType_Handshake ver fragment) = do
	handshakes <- returnEither (decodeHandshakes $ fragmentGetBytes fragment)
	hss <- forM handshakes $ \(ty, content) -> do
		hs <- processHandshake ver ty content
		when (finishHandshakeTypeMaterial ty) $ updateHandshakeDigestSplitted ty content
		return hs
	return $ Handshake hss

processHandshake :: Version -> HandshakeType -> ByteString -> TLSSt Handshake
processHandshake ver ty econtent = do
	-- SECURITY FIXME if RSA fail, we need to generate a random master secret and not fail.
	e <- updateStatusHs ty
	maybe (return ()) throwError e

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
		ClientHello cver ran _ _ _ ex -> unless clientmode $ do
			mapM_ processClientExtension ex
			startHandshakeClient cver ran
		ServerHello sver ran _ _ _ ex -> when clientmode $ do
			-- FIXME notify the user to take action if the extension requested is missing
			-- secreneg <- getSecureRenegotiation
			-- when (secreneg && (isNothing $ lookup 0xff01 ex)) $ ...
			mapM_ processServerExtension ex
			setServerRandom ran
			setVersion sver
		Certificates certs            -> when clientmode $ do processCertificates certs
		ClientKeyXchg cver _          -> unless clientmode $ do
			processClientKeyXchg cver content
		Finished fdata                -> processClientFinished fdata
		_                             -> return ()
	return hs
	where
		-- secure renegotiation
		processClientExtension (0xff01, content) = do
			v <- getVerifiedData True
			let bs = encodeExtSecureRenegotiation v Nothing
			when (bs /= content) $ throwError $
				Error_Protocol ("client verified data not matching: " ++ show v ++ ":" ++ show content, True, HandshakeFailure)
			setSecureRenegotiation True
		-- unknown extensions
		processClientExtension _ = return ()

		processServerExtension (0xff01, content) = do
			cv <- getVerifiedData True
			sv <- getVerifiedData False
			let bs = encodeExtSecureRenegotiation cv (Just sv)
			when (bs /= content) $ throwError $ Error_Protocol ("server secure renegotiation data not matching", True, HandshakeFailure)
			return ()

		processServerExtension _ = return ()

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
	when (expected /= fdata) $ do
		throwError $ Error_Protocol("bad record mac", True, BadRecordMac)
	updateVerifiedData False fdata
	return ()

-- just `decompress' by returning the data for now till we have compression implemented
uncompressContent :: Record Compressed -> TLSSt (Record Plaintext)
uncompressContent record = onRecordFragment record $ fragmentUncompress $ \bytes ->
	withCompression $ compressionInflate bytes

decryptContent :: Record Ciphertext -> TLSSt (Record Compressed)
decryptContent record = onRecordFragment record $ fragmentUncipher $ \e -> do
	st <- get
	if stRxEncrypted st
		then decryptData e >>= getCipherData record
		else return e

getCipherData :: Record a -> CipherData -> TLSSt ByteString
getCipherData (Record pt ver _) cdata = do
	-- check if the MAC is valid.
	macValid <- case cipherDataMAC cdata of
		Nothing     -> return True
		Just digest -> do
			let new_hdr = Header pt ver (fromIntegral $ B.length $ cipherDataContent cdata)
			expected_digest <- makeDigest False new_hdr $ cipherDataContent cdata
			return (expected_digest `bytesEq` digest)

	-- check if the padding is filled with the correct pattern if it exists
	paddingValid <- case cipherDataPadding cdata of
		Nothing  -> return True
		Just pad -> do
			cver <- stVersion <$> get
			let b = B.length pad - 1
			return (if cver < TLS10 then True else B.replicate (B.length pad) (fromIntegral b) `bytesEq` pad)

	unless (macValid &&! paddingValid) $ do
		throwError $ Error_Protocol ("bad record mac", True, BadRecordMac)

	return $ cipherDataContent cdata

decryptData :: Bytes -> TLSSt CipherData
decryptData econtent = do
	st <- get

	let cipher     = fromJust "cipher" $ stCipher st
	let bulk       = cipherBulk cipher
	let cst        = fromJust "rx crypt state" $ stRxCryptState st
	let digestSize = hashSize $ cipherHash cipher
	let writekey   = cstKey cst

	case bulkF bulk of
		BulkNoneF -> do
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
		BulkBlockF _ decryptF -> do
			{- update IV -}
			let (iv, econtent') =
				if hasExplicitBlockIV $ stVersion st
					then B.splitAt (bulkIVSize bulk) econtent
					else (cstIV cst, econtent)
			let newiv = fromJust "new iv" $ takelast (bulkBlockSize bulk) econtent'
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
		BulkStreamF initF _ decryptF -> do
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
		PubKeyRSA pubkey -> setPublicKey (PubRSA pubkey)
		_                -> return ()
