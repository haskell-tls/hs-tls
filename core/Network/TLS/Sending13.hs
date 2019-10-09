-- |
-- Module      : Network.TLS.Sending13
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Sending module contains calls related to marshalling packets according
-- to the TLS state
--
module Network.TLS.Sending13
       ( encodePacket13
       , updateHandshake13
       ) where

import Network.TLS.Context.Internal
import Network.TLS.Handshake.Random
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.Imports
import Network.TLS.Packet
import Network.TLS.Packet13
import Network.TLS.Record.Engage
import Network.TLS.Record.Types
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Util

import qualified Data.ByteString as B

encodePacket13 :: Context -> Packet13 -> IO (Either TLSError ByteString)
encodePacket13 ctx pkt@(Handshake13 hss) = do
    forM_ hss $ updateHandshake13 ctx
    encodePacket13' ctx pkt
encodePacket13 ctx pkt = encodePacket13' ctx pkt

encodePacket13' :: Context -> Packet13 -> IO (Either TLSError ByteString)
encodePacket13' ctx pkt = do
    let pt = contentType pkt
        mkRecord = Record pt TLS12
        records = dividePacket13 16384 pkt mkRecord
    fmap B.concat <$> forEitherM records (encodeRecord13 ctx)

dividePacket13 :: Int -> Packet13 -> (Fragment Plaintext -> Record Plaintext) -> [Record Plaintext]
dividePacket13 len pkt mkRecord = mkRecord . fragmentPlaintext <$> encodePacketContent pkt
  where
    encodePacketContent (Handshake13 hss)  = getChunks len (encodeHandshakes13 hss)
    encodePacketContent (Alert13 a)        = [encodeAlerts a]
    encodePacketContent (AppData13 x)      = [x]
    encodePacketContent ChangeCipherSpec13 = [encodeChangeCipherSpec]

encodeRecord13 :: Context -> Record Plaintext -> IO (Either TLSError ByteString)
encodeRecord13 ctx record = runTxState ctx $ do
    erecord <- engageRecord record
    let (hdr, content) = recordToRaw erecord
    return $ B.concat [ encodeHeader hdr, content ]

updateHandshake13 :: Context -> Handshake13 -> IO ()
updateHandshake13 ctx hs
    | isIgnored hs = return ()
    | otherwise    = usingHState ctx $ do
        when (isHRR hs) wrapAsMessageHash13
        updateHandshakeDigest encoded
        addHandshakeMessage encoded
  where
    encoded = encodeHandshake13 hs

    isHRR (ServerHello13 srand _ _ _) = isHelloRetryRequest srand
    isHRR _                           = False

    isIgnored NewSessionTicket13{} = True
    isIgnored KeyUpdate13{}        = True
    isIgnored _                    = False
