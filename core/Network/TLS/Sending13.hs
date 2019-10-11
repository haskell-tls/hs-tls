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
import Network.TLS.Record.Types
import Network.TLS.Sending
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Util

import qualified Data.ByteString as B

encodePacket13 :: Context -> Packet13 -> IO (Either TLSError ByteString)
encodePacket13 ctx pkt = do
    let pt = contentType pkt
        mkRecord bs = Record pt TLS12 (fragmentPlaintext bs)
    records <- map mkRecord <$> packetToFragments ctx 16384 pkt
    fmap B.concat <$> forEitherM records (encodeRecord ctx)

encodeRecord :: Context -> Record Plaintext -> IO (Either TLSError ByteString)
encodeRecord ctx = runTxState ctx . encodeRecordM

packetToFragments :: Context -> Int -> Packet13 -> IO [ByteString]
packetToFragments ctx len pkt = encodePacketContent pkt
  where
    encodePacketContent (Handshake13 hss)  =
        getChunks len . B.concat <$> mapM (updateHandshake13 ctx) hss
    encodePacketContent (Alert13 a)        = return [encodeAlerts a]
    encodePacketContent (AppData13 x)      = return [x]
    encodePacketContent ChangeCipherSpec13 = return [encodeChangeCipherSpec]

updateHandshake13 :: Context -> Handshake13 -> IO ByteString
updateHandshake13 ctx hs
    | isIgnored hs = return encoded
    | otherwise    = usingHState ctx $ do
        when (isHRR hs) wrapAsMessageHash13
        updateHandshakeDigest encoded
        addHandshakeMessage encoded
        return encoded
  where
    encoded = encodeHandshake13 hs

    isHRR (ServerHello13 srand _ _ _) = isHelloRetryRequest srand
    isHRR _                           = False

    isIgnored NewSessionTicket13{} = True
    isIgnored KeyUpdate13{}        = True
    isIgnored _                    = False
