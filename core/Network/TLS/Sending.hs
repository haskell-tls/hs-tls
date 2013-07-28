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
module Network.TLS.Sending (writePacket) where

import Control.Monad.State

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Network.TLS.Types (Role(..))
import Network.TLS.Cap
import Network.TLS.Struct
import Network.TLS.Record
import Network.TLS.Packet
import Network.TLS.State
import Network.TLS.Handshake.State
import Network.TLS.Cipher

-- | 'makePacketData' create a Header and a content bytestring related to a packet
-- this doesn't change any state
makeRecord :: Packet -> RecordM (Record Plaintext)
makeRecord pkt = do
    ver <- getRecordVersion
    return $ Record (packetType pkt) ver (fragmentPlaintext $ writePacketContent pkt)
  where writePacketContent (Handshake hss)    = encodeHandshakes hss
        writePacketContent (Alert a)          = encodeAlerts a
        writePacketContent (ChangeCipherSpec) = encodeChangeCipherSpec
        writePacketContent (AppData x)        = x

-- | marshall packet data
encodeRecord :: Record Ciphertext -> RecordM ByteString
encodeRecord record = return $ B.concat [ encodeHeader hdr, content ]
  where (hdr, content) = recordToRaw record

-- | writePacket transform a packet into marshalled data related to current state
-- and updating state on the go
writePacket :: Packet -> TLSSt ByteString
writePacket pkt@(Handshake hss) = do
    forM_ hss $ \hs -> do
        case hs of
            Finished fdata -> updateVerifiedData ClientRole fdata
            _              -> return ()
        let encoded = encodeHandshake hs
        when (certVerifyHandshakeMaterial hs) $ withHandshakeM $ addHandshakeMessage encoded
        when (finishHandshakeTypeMaterial $ typeOfHandshake hs) $ withHandshakeM $ updateHandshakeDigest encoded
    prepareRecord (makeRecord pkt >>= engageRecord >>= encodeRecord)
writePacket pkt = do
    d <- prepareRecord (makeRecord pkt >>= engageRecord >>= encodeRecord)
    when (pkt == ChangeCipherSpec) $ switchTxEncryption
    return d

-- before TLS 1.1, the block cipher IV is made of the residual of the previous block,
-- so we use cstIV as is, however in other case we generate an explicit IV
prepareRecord :: RecordM a -> TLSSt a
prepareRecord f = do
    st  <- get
    ver <- getVersion
    let sz = case stCipher $ stTxState st of
                  Nothing     -> 0
                  Just cipher -> bulkIVSize $ cipherBulk cipher
    if hasExplicitBlockIV ver && sz > 0
        then do newIV <- genRandom sz
                runTxState (modify $ setRecordIV newIV)
                runTxState f
        else runTxState f
