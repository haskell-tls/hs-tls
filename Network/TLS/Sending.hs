{-# LANGUAGE FlexibleContexts #-}

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
import Data.Maybe

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
makePacketData :: MonadTLSState m => Packet -> m (Header, ByteString)
makePacketData pkt = do
	ver <- getTLSState >>= return . stVersion
	content <- writePacketContent pkt
	let hdr = Header (packetType pkt) ver (fromIntegral $ B.length content)
	return (hdr, content)

{-
 - Handshake data need to update a digest
 -}
processPacketData :: MonadTLSState m => (Header, ByteString) -> m (Header, ByteString)
processPacketData dat@(Header ty _ _, content) = do
	when (ty == ProtocolType_Handshake) (updateHandshakeDigest content)
	return dat

{-
 - when Tx Encrypted is set, we pass the data through encryptContent, otherwise
 - we just return the packet
 -}
encryptPacketData :: MonadTLSState m => (Header, ByteString) -> m (Header, ByteString)
encryptPacketData dat = do
	st <- getTLSState
	if stTxEncrypted st
		then encryptContent dat
		else return dat

{-
 - ChangeCipherSpec state change need to be handled after encryption otherwise
 - its own packet would be encrypted with the new context, instead of beeing sent
 - under the current context
 -}
postprocessPacketData :: MonadTLSState m => (Header, ByteString) -> m (Header, ByteString)
postprocessPacketData dat@(Header ProtocolType_ChangeCipherSpec _ _, _) =
	switchTxEncryption >> isClientContext >>= \cc -> when cc setKeyBlock >> return dat

postprocessPacketData dat = return dat

{-
 - marshall packet data
 -}
encodePacket :: MonadTLSState m => (Header, ByteString) -> m ByteString
encodePacket (hdr, content) = return $ B.concat [ encodeHeader hdr, content ]


{-
 - writePacket transform a packet into marshalled data related to current state
 - and updating state on the go
 -}
writePacket :: MonadTLSState m => Packet -> m ByteString
writePacket pkt = makePacketData pkt >>= processPacketData >>=
                  encryptPacketData >>= postprocessPacketData >>= encodePacket

{------------------------------------------------------------------------------}
{- SENDING Helpers                                                            -}
{------------------------------------------------------------------------------}

{- if the RSA encryption fails we just return an empty bytestring, and let the protocol
 - fail by itself; however it would be probably better to just report it since it's an internal problem.
 -}
encryptRSA :: MonadTLSState m => ByteString -> m ByteString
encryptRSA content = do
	st <- getTLSState
	let g = stRandomGen st
	let rsakey = fromJust $ hstRSAPublicKey $ fromJust $ stHandshake st
	case rsaEncrypt g rsakey content of
		Nothing             -> fail "no RSA key selected"
		Just (econtent, g') -> do
			putTLSState (st { stRandomGen = g' })
			return econtent

encryptContent :: MonadTLSState m => (Header, ByteString) -> m (Header, ByteString)
encryptContent (hdr@(Header pt ver _), content) = do
	digest <- makeDigest True hdr content
	encrypted_msg <- encryptData $ B.concat [content, digest]
	let hdrnew = Header pt ver (fromIntegral $ B.length encrypted_msg)
	return (hdrnew, encrypted_msg)

encryptData :: MonadTLSState m => ByteString -> m ByteString
encryptData content = do
	st <- getTLSState

	assert "encrypt data"
		[ ("cipher", isNothing $ stCipher st)
		, ("crypt state", isNothing $ stTxCryptState st) ]

	let cipher = fromJust $ stCipher st
	let cst = fromJust $ stTxCryptState st
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
		CipherNoneF -> fail "none encrypt"
		CipherBlockF encrypt _ -> do
			let iv = cstIV cst
			let e = encrypt writekey iv (B.concat [ content, padding ])
			let newiv = fromJust $ takelast (fromIntegral $ cipherIVSize cipher) e
			putTLSState $ st { stTxCryptState = Just $ cst { cstIV = newiv } }
			return $ if hasExplicitBlockIV $ stVersion st
				then B.concat [iv,e]
				else e
		CipherStreamF initF encryptF _ -> do
			let iv = cstIV cst
			let (e, newiv) = encryptF (if iv /= B.empty then iv else initF writekey) content
			putTLSState $ st { stTxCryptState = Just $ cst { cstIV = newiv } }
			return e
	return econtent

encodePacketContent :: Packet -> ByteString
encodePacketContent (Handshake h)      = encodeHandshake h
encodePacketContent (Alert a)          = encodeAlert a
encodePacketContent (ChangeCipherSpec) = encodeChangeCipherSpec
encodePacketContent (AppData x)        = x

writePacketContent :: MonadTLSState m => Packet -> m ByteString
writePacketContent (Handshake ckx@(ClientKeyXchg _ _)) = do
	let premastersecret = runPut $ encodeHandshakeContent ckx
	setMasterSecret premastersecret
	econtent <- encryptRSA premastersecret
	let extralength = runPut $ putWord16 $ fromIntegral $ B.length econtent
	let hdr = runPut $ encodeHandshakeHeader (typeOfHandshake ckx) (fromIntegral (B.length econtent + 2))
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
