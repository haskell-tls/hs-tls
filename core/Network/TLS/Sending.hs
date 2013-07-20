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
module Network.TLS.Sending (writePacket, encryptRSA, signRSA) where

import Control.Applicative ((<$>))
import Control.Monad.State

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Network.TLS.Util
import Network.TLS.Struct
import Network.TLS.Record
import Network.TLS.Packet
import Network.TLS.State
import Network.TLS.Handshake.State
import Network.TLS.Crypto

{-
 - 'makePacketData' create a Header and a content bytestring related to a packet
 - this doesn't change any state
 -}
makeRecord :: Packet -> RecordM (Record Plaintext)
makeRecord pkt = do
    ver <- stVersion <$> get
    content <- writePacketContent pkt
    return $ Record (packetType pkt) ver (fragmentPlaintext content)

{-
 - ChangeCipherSpec state change need to be handled after encryption otherwise
 - its own packet would be encrypted with the new context, instead of beeing sent
 - under the current context
 -}
postprocessRecord :: Record Ciphertext -> RecordM (Record Ciphertext)
postprocessRecord record@(Record ProtocolType_ChangeCipherSpec _ _) =
    switchTxEncryption >> return record
postprocessRecord record = return record

{-
 - marshall packet data
 -}
encodeRecord :: Record Ciphertext -> RecordM ByteString
encodeRecord record = return $ B.concat [ encodeHeader hdr, content ]
  where (hdr, content) = recordToRaw record

{-
 - just update TLS state machine
 -}
preProcessPacket :: Packet -> TLSSt ()
preProcessPacket (Alert _)          = return ()
preProcessPacket (AppData _)        = return ()
preProcessPacket (ChangeCipherSpec) = return ()
preProcessPacket (Handshake hss)    = forM_ hss $ \hs -> do
    case hs of
        Finished fdata -> updateVerifiedData True fdata
        _              -> return ()
    let encoded = encodeHandshake hs
    when (certVerifyHandshakeMaterial hs) $ withHandshakeM $ addHandshakeMessage encoded
    when (finishHandshakeTypeMaterial $ typeOfHandshake hs) $ withHandshakeM $ updateHandshakeDigest encoded

{-
 - writePacket transform a packet into marshalled data related to current state
 - and updating state on the go
 -}
writePacket :: Packet -> TLSSt ByteString
writePacket pkt = do
        preProcessPacket pkt
        runRecordStateSt (makeRecord pkt >>= engageRecord >>= postprocessRecord >>= encodeRecord)

{------------------------------------------------------------------------------}
{- SENDING Helpers                                                            -}
{------------------------------------------------------------------------------}

{- if the RSA encryption fails we just return an empty bytestring, and let the protocol
 - fail by itself; however it would be probably better to just report it since it's an internal problem.
 -}
encryptRSA :: ByteString -> TLSSt ByteString
encryptRSA content = do
    rsakey <- fromJust "rsa public key" . hstRSAPublicKey . fromJust "handshake" . stHandshake <$> get
    runRecordStateSt $ do
        st <- get
        let (v,rng') = withTLSRNG (stRandomGen st) (\g -> kxEncrypt g rsakey content)
        put (st { stRandomGen = rng' })
        case v of
            Left err       -> fail ("rsa encrypt failed: " ++ show err)
            Right econtent -> return econtent

signRSA :: HashDescr -> ByteString -> TLSSt ByteString
signRSA hsh content = do
    rsakey <- fromJust "rsa client private key" . hstRSAClientPrivateKey . fromJust "handshake" . stHandshake <$> get
    runRecordStateSt $ do
        st <- get
        let (r, rng') = withTLSRNG (stRandomGen st) (\g -> kxSign g rsakey hsh content)
        put (st { stRandomGen = rng' })
        case r of
            Left err       -> fail ("rsa sign failed: " ++ show err)
            Right econtent -> return econtent

writePacketContent :: Monad m => Packet -> m ByteString
writePacketContent (Handshake hss)    = return $ encodeHandshakes hss
writePacketContent (Alert a)          = return $ encodeAlerts a
writePacketContent (ChangeCipherSpec) = return $ encodeChangeCipherSpec
writePacketContent (AppData x)        = return x
