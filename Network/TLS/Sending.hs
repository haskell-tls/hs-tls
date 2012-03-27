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
module Network.TLS.Sending (writePacket, encryptRSA) where

import Control.Applicative ((<$>))
import Control.Monad.State

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Network.TLS.Util
import Network.TLS.Struct
import Network.TLS.Record
import Network.TLS.Packet
import Network.TLS.State
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

{-
 - ChangeCipherSpec state change need to be handled after encryption otherwise
 - its own packet would be encrypted with the new context, instead of beeing sent
 - under the current context
 -}
postprocessRecord :: Record Ciphertext -> TLSSt (Record Ciphertext)
postprocessRecord record@(Record ProtocolType_ChangeCipherSpec _ _) =
        switchTxEncryption >> return record
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
preProcessPacket (ChangeCipherSpec) = return ()
preProcessPacket (Handshake hss)    = forM_ hss $ \hs -> do
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
        makeRecord pkt >>= processRecord >>= engageRecord >>= postprocessRecord >>= encodeRecord

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

writePacketContent :: Packet -> TLSSt ByteString
writePacketContent (Handshake hss)    = return $ encodeHandshakes hss
writePacketContent (Alert a)          = return $ encodeAlerts a
writePacketContent (ChangeCipherSpec) = return $ encodeChangeCipherSpec
writePacketContent (AppData x)        = return x
