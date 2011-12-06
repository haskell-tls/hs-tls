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
module Network.TLS.Receiving (processHandshake, processPacket) where

import Control.Applicative ((<$>))
import Control.Monad.State
import Control.Monad.Error

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Network.TLS.Util
import Network.TLS.Struct
import Network.TLS.Record
import Network.TLS.Packet
import Network.TLS.State
import Network.TLS.Cipher
import Network.TLS.Crypto
import Data.Certificate.X509

returnEither :: Either TLSError a -> TLSSt a
returnEither (Left err) = throwError err
returnEither (Right a)  = return a

processPacket :: Record Plaintext -> TLSSt Packet

processPacket (Record ProtocolType_AppData _ fragment) = return $ AppData $ fragmentGetBytes fragment

processPacket (Record ProtocolType_Alert _ fragment) = return . Alert =<< returnEither (decodeAlerts $ fragmentGetBytes fragment)

processPacket (Record ProtocolType_ChangeCipherSpec _ fragment) = do
	returnEither $ decodeChangeCipherSpec $ fragmentGetBytes fragment
	switchRxEncryption
	isClientContext >>= \cc -> when (not cc) setKeyBlock
	return ChangeCipherSpec

processPacket (Record ProtocolType_Handshake ver fragment) = do
	keyxchg <- getCipherKeyExchangeType
	let currentparams = CurrentParams
		{ cParamsVersion     = ver
		, cParamsKeyXchgType = maybe CipherKeyExchange_RSA id $ keyxchg
		}
	handshakes <- returnEither (decodeHandshakes $ fragmentGetBytes fragment)
	hss <- forM handshakes $ \(ty, content) -> do
		case decodeHandshake currentparams ty content of
			Left err -> throwError err
			Right hs -> return hs
	return $ Handshake hss

processHandshake :: Handshake -> TLSSt ()
processHandshake hs = do
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
		ClientKeyXchg content         -> unless clientmode $ do
			processClientKeyXchg content
		Finished fdata                -> processClientFinished fdata
		_                             -> return ()
	when (finishHandshakeTypeMaterial $ typeOfHandshake hs) (updateHandshakeDigest $ encodeHandshake hs)
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
processClientKeyXchg :: ByteString -> TLSSt ()
processClientKeyXchg encryptedPremaster = do
	expectedVer <- hstClientVersion . fromJust "handshake" . stHandshake <$> get
	random      <- genTLSRandom 48
	ePremaster  <- decryptRSA encryptedPremaster
	case ePremaster of
		Left _          -> setMasterSecret random
		Right premaster -> case decodePreMasterSecret premaster of
			Left _                       -> setMasterSecret random
			Right (ver, _)
				| ver /= expectedVer -> setMasterSecret random
				| otherwise          -> setMasterSecret premaster

processClientFinished :: FinishedData -> TLSSt ()
processClientFinished fdata = do
	cc <- stClientContext <$> get
	expected <- getHandshakeDigest (not cc)
	when (expected /= fdata) $ do
		throwError $ Error_Protocol("bad record mac", True, BadRecordMac)
	updateVerifiedData False fdata
	return ()

processCertificates :: [X509] -> TLSSt ()
processCertificates certs = do
	let (X509 mainCert _ _ _ _) = head certs
	case certPubKey mainCert of
		PubKeyRSA pubkey -> setPublicKey (PubRSA pubkey)
		_                -> return ()
