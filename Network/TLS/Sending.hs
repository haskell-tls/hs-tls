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

import Control.Applicative ((<$>))
import Control.Monad.State

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Network.TLS.Util
import Network.TLS.Cap
import Network.TLS.Wire
import Network.TLS.Struct
import Network.TLS.Record
import Network.TLS.Packet
import Network.TLS.State
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Crypto

{-
 - 'makePacketData' create a Header and a content bytestring related to a packet
 - this doesn't change any state
 -}
makeRecord :: Packet -> TLSSt (Record Plaintext)
makeRecord pkt = do
	ver <- stVersion <$> get
	content <- writePacketContent pkt
	return $ Record (packetType pkt) ver (fragmentPlaintext content)

{-
 - Handshake data need to update a digest
 -}
processRecord :: Record Plaintext -> TLSSt (Record Plaintext)
processRecord record@(Record ty _ fragment) = do
	when (ty == ProtocolType_Handshake) (updateHandshakeDigest $ fragmentGetBytes fragment)
	return record

compressRecord :: Record Plaintext -> TLSSt (Record Compressed)
compressRecord record =
	onRecordFragment record $ fragmentCompress $ \bytes -> do
		withCompression $ compressionDeflate bytes

{-
 - when Tx Encrypted is set, we pass the data through encryptContent, otherwise
 - we just return the packet
 -}
encryptRecord :: Record Compressed -> TLSSt (Record Ciphertext)
encryptRecord record = onRecordFragment record $ fragmentCipher $ \bytes -> do
	st <- get
	if stTxEncrypted st
		then encryptContent record bytes
		else return bytes

{-
 - ChangeCipherSpec state change need to be handled after encryption otherwise
 - its own packet would be encrypted with the new context, instead of beeing sent
 - under the current context
 -}
postprocessRecord :: Record Ciphertext -> TLSSt (Record Ciphertext)
postprocessRecord record@(Record ProtocolType_ChangeCipherSpec _ _) =
	switchTxEncryption >> isClientContext >>= \cc -> when cc setKeyBlock >> return record
postprocessRecord record = return record

{-
 - marshall packet data
 -}
encodeRecord :: Record Ciphertext -> TLSSt ByteString
encodeRecord record = return $ B.concat [ encodeHeader hdr, content ]
	where (hdr, content) = recordToRaw record

{-
 - just update TLS state machine
 -}
preProcessPacket :: Packet -> TLSSt ()
preProcessPacket (Alert _)          = return ()
preProcessPacket (AppData _)        = return ()
preProcessPacket (ChangeCipherSpec) = updateStatusCC True >> return () -- FIXME don't ignore this error just in case
preProcessPacket (Handshake hss)    = forM_ hss $ \hs -> do
	-- FIXME don't ignore this error
	_ <- updateStatusHs (typeOfHandshake hs)
	case hs of
		Finished fdata -> updateVerifiedData True fdata
		_              -> return ()

{-
 - writePacket transform a packet into marshalled data related to current state
 - and updating state on the go
 -}
writePacket :: Packet -> TLSSt ByteString
writePacket pkt = do
	preProcessPacket pkt
	makeRecord pkt >>= processRecord >>= compressRecord >>= encryptRecord >>= postprocessRecord >>= encodeRecord

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

encryptContent :: Record Compressed -> ByteString -> TLSSt ByteString
encryptContent record content = do
	digest <- makeDigest True (recordToHeader record) content
	encryptData $ B.concat [content, digest]

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

	case cipherF cipher of
		CipherNoneF -> return content
		CipherBlockF encrypt _ -> do
			-- before TLS 1.1, the block cipher IV is made of the residual of the previous block.
			iv <- if hasExplicitBlockIV $ stVersion st
				then genTLSRandom (fromIntegral $ cipherIVSize cipher)
				else return $ cstIV cst
			let e = encrypt writekey iv (B.concat [ content, padding ])
			if hasExplicitBlockIV $ stVersion st
				then return $ B.concat [iv,e]
				else do
					let newiv = fromJust "new iv" $ takelast (fromIntegral $ cipherIVSize cipher) e
					put $ st { stTxCryptState = Just $ cst { cstIV = newiv } }
					return e
		CipherStreamF initF encryptF _ -> do
			let iv = cstIV cst
			let (e, newiv) = encryptF (if iv /= B.empty then iv else initF writekey) content
			put $ st { stTxCryptState = Just $ cst { cstIV = newiv } }
			return e

writePacketContent :: Packet -> TLSSt ByteString
writePacketContent (Handshake hss) = return . B.concat =<< mapM makeContent hss where
	makeContent hs@(ClientKeyXchg _ _) = do
		ver <- get >>= return . stVersion
		let premastersecret = runPut $ encodeHandshakeContent hs
		setMasterSecret premastersecret
		econtent <- encryptRSA premastersecret

		let extralength =
			if ver < TLS10
			then B.empty
			else runPut $ putWord16 $ fromIntegral $ B.length econtent
		let hdr = runPut $ encodeHandshakeHeader (typeOfHandshake hs)
							 (fromIntegral (B.length econtent + B.length extralength))
		return $ B.concat [hdr, extralength, econtent]
	makeContent hs = return $ encodeHandshakes [hs]

writePacketContent (Alert a)          = return $ encodeAlerts a
writePacketContent (ChangeCipherSpec) = return $ encodeChangeCipherSpec
writePacketContent (AppData x)        = return x
