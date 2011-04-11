-- |
-- Module      : Network.TLS.Sending
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Sending module contains calls related to marshalling packets according
-- to the TLS state 
--
module Network.TLS.Sending (
	writePacket
	) where

import Control.Monad.State

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Network.TLS.Util
import Network.TLS.Cap
import Network.TLS.Wire
import Network.TLS.Struct
import Network.TLS.Packet
import Network.TLS.State
import Network.TLS.Cipher
import Network.TLS.Crypto

{-
 - 'makePacketData' create a Header and a content bytestring related to a packet
 - this doesn't change any state
 -}
makePacketData :: Packet -> TLSSt (Header, ByteString)
makePacketData pkt = do
	ver <- get >>= return . stVersion
	content <- writePacketContent pkt
	let hdr = Header (packetType pkt) ver (fromIntegral $ B.length content)
	return (hdr, content)

{-
 - Handshake data need to update a digest
 -}
processPacketData :: (Header, ByteString) -> TLSSt (Header, ByteString)
processPacketData dat@(Header ty _ _, content) = do
	when (ty == ProtocolType_Handshake) (updateHandshakeDigest content)
	return dat

{-
 - when Tx Encrypted is set, we pass the data through encryptContent, otherwise
 - we just return the packet
 -}
encryptPacketData :: (Header, ByteString) -> TLSSt (Header, ByteString)
encryptPacketData dat = do
	st <- get
	if stTxEncrypted st
		then encryptContent dat
		else return dat

{-
 - ChangeCipherSpec state change need to be handled after encryption otherwise
 - its own packet would be encrypted with the new context, instead of beeing sent
 - under the current context
 -}
postprocessPacketData :: (Header, ByteString) -> TLSSt (Header, ByteString)
postprocessPacketData dat@(Header ProtocolType_ChangeCipherSpec _ _, _) =
	switchTxEncryption >> isClientContext >>= \cc -> when cc setKeyBlock >> return dat

postprocessPacketData dat = return dat

{-
 - marshall packet data
 -}
encodePacket :: (Header, ByteString) -> TLSSt ByteString
encodePacket (hdr, content) = return $ B.concat [ encodeHeader hdr, content ]

{-
 - just update TLS state machine
 -}
preProcessPacket :: Packet -> TLSSt Packet
preProcessPacket pkt = do
	e <- case pkt of
		Handshake hs     -> updateStatusHs (typeOfHandshake hs)
		AppData _        -> return Nothing
		ChangeCipherSpec -> updateStatusCC True
		Alert _          -> return Nothing
	return pkt

{-
 - writePacket transform a packet into marshalled data related to current state
 - and updating state on the go
 -}
writePacket :: Packet -> TLSSt ByteString
writePacket pkt = preProcessPacket pkt >>= makePacketData >>= processPacketData >>=
                  encryptPacketData >>= postprocessPacketData >>= encodePacket

{------------------------------------------------------------------------------}
{- SENDING Helpers                                                            -}
{------------------------------------------------------------------------------}

{- if the RSA encryption fails we just return an empty bytestring, and let the protocol
 - fail by itself; however it would be probably better to just report it since it's an internal problem.
 -}
encryptRSA :: ByteString -> TLSSt ByteString
encryptRSA content = do
	st <- get
	let rsakey = fromJust "rsa public key" $ hstRSAPublicKey $ fromJust "handshake" $ stHandshake st
	case withTLSRNG (stRandomGen st) (\g -> kxEncrypt g rsakey content) of
		Left err               -> fail ("rsa encrypt failed: " ++ show err)
		Right (econtent, rng') -> put (st { stRandomGen = rng' }) >> return econtent

encryptContent :: (Header, ByteString) -> TLSSt (Header, ByteString)
encryptContent (hdr@(Header pt ver _), content) = do
	digest <- makeDigest True hdr content
	encrypted_msg <- encryptData $ B.concat [content, digest]
	let hdrnew = Header pt ver (fromIntegral $ B.length encrypted_msg)
	return (hdrnew, encrypted_msg)

encryptData :: ByteString -> TLSSt ByteString
encryptData content = do
	st <- get

	let cipher = fromJust "cipher" $ stCipher st
	let cst = fromJust "tx crypt state" $ stTxCryptState st
	let padding_size = fromIntegral $ cipherPaddingSize cipher

	let msg_len = B.length content
	let padding = if padding_size > 0
		then
			let padbyte = padding_size - (msg_len `mod` padding_size) in
			let padbyte' = if padbyte == 0 then padding_size else padbyte in
			B.replicate padbyte' (fromIntegral (padbyte' - 1))
		else
			B.empty
	let writekey = cstKey cst

	econtent <- case cipherF cipher of
		CipherNoneF -> return content
		CipherBlockF encrypt _ -> do
			let iv = cstIV cst
			let e = encrypt writekey iv (B.concat [ content, padding ])
			let newiv = fromJust "new iv" $ takelast (fromIntegral $ cipherIVSize cipher) e
			put $ st { stTxCryptState = Just $ cst { cstIV = newiv } }
			return $ if hasExplicitBlockIV $ stVersion st
				then B.concat [iv,e]
				else e
		CipherStreamF initF encryptF _ -> do
			let iv = cstIV cst
			let (e, newiv) = encryptF (if iv /= B.empty then iv else initF writekey) content
			put $ st { stTxCryptState = Just $ cst { cstIV = newiv } }
			return e
	return econtent

encodePacketContent :: Packet -> ByteString
encodePacketContent (Handshake h)      = encodeHandshake h
encodePacketContent (Alert a)          = encodeAlert a
encodePacketContent (ChangeCipherSpec) = encodeChangeCipherSpec
encodePacketContent (AppData x)        = x

writePacketContent :: Packet -> TLSSt ByteString
writePacketContent (Handshake ckx@(ClientKeyXchg _ _)) = do
	ver <- get >>= return . stVersion 
	let premastersecret = runPut $ encodeHandshakeContent ckx
	setMasterSecret premastersecret
	econtent <- encryptRSA premastersecret

	let extralength =
		if ver < TLS10
		then B.empty
		else runPut $ putWord16 $ fromIntegral $ B.length econtent
	let hdr = runPut $ encodeHandshakeHeader (typeOfHandshake ckx)
	                                         (fromIntegral (B.length econtent + B.length extralength))
	return $ B.concat [hdr, extralength, econtent]

writePacketContent pkt@(Handshake (ClientHello ver crand _ _ _ _)) = do
	cc <- isClientContext
	when cc (startHandshakeClient ver crand)
	return $ encodePacketContent pkt

writePacketContent pkt@(Handshake (ServerHello ver srand _ _ _ _)) = do
	cc <- isClientContext
	unless cc $ do
		setVersion ver
		setServerRandom srand
	return $ encodePacketContent pkt

writePacketContent pkt = return $ encodePacketContent pkt
