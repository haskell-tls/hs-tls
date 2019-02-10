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
module Network.TLS.Sending (writePacket, writePacketDTLS) where

import Control.Monad.State.Strict
import Control.Concurrent.MVar
import Data.IORef

import qualified Data.ByteString as B

import Network.TLS.Types (Role(..))
import Network.TLS.Cap
import Network.TLS.Struct
import Network.TLS.Record
import Network.TLS.Packet
import Network.TLS.Context.Internal
import Network.TLS.Parameters
import Network.TLS.State
import Network.TLS.Handshake.State
import Network.TLS.Cipher
import Network.TLS.Util
import Network.TLS.Imports

-- | 'makePacketData' create a Header and a content bytestring related to a packet
-- this doesn't change any state
makeRecord :: Packet -> RecordM (Record Plaintext)
makeRecord pkt = do
    ver <- getRecordVersion
    return $ Record (packetType pkt) ver 0 (fragmentPlaintext $ writePacketContent pkt)
  where writePacketContent (Handshake hss)    = encodeHandshakes hss
        writePacketContent (Alert a)          = encodeAlerts a
        writePacketContent  ChangeCipherSpec  = encodeChangeCipherSpec
        writePacketContent (AppData x)        = x


makeRecordFragmentDTLS :: ProtocolType -> Fragment Plaintext -> RecordM (Record Plaintext)
makeRecordFragmentDTLS ty fragment = do
  ver <- getRecordVersion
  sn <- incrSeqNumber
  return $ Record ty ver sn fragment


makeNonHsRecordDTLS :: Word16 -> Packet -> RecordM (Record Plaintext)
makeNonHsRecordDTLS _ pkt = makeRecordFragmentDTLS (packetType pkt) (fragmentPlaintext $ packetContent pkt)
  where packetContent (Alert a)          = encodeAlerts a
        packetContent  ChangeCipherSpec  = encodeChangeCipherSpec
        packetContent (AppData x)        = x
        packetContent _                  = error "makeNonHsRecordDTLS called for Handshake packet"

makeHsRecordDTLS :: Word16 -> [Handshake] -> [RecordM (Record Plaintext)]
makeHsRecordDTLS mtu hss = map (makeRecordFragmentDTLS ProtocolType_Handshake) $
                           map fragmentPlaintext $ mconcat $ map (encodeHandshakeDTLS mtu) hss

-- | marshall packet data
encodeRecord :: Record Ciphertext -> RecordM ByteString
encodeRecord record = return $ B.concat [ encodeHeader hdr, content ]
  where (hdr, content) = recordToRaw record

-- | writePacket transform a packet into marshalled data related to current state
-- and updating state on the go
writePacket :: Context -> Packet -> IO (Either TLSError ByteString)
writePacket ctx pkt@(Handshake hss) = do
    forM_ hss $ \hs -> do
        case hs of
            Finished fdata -> usingState_ ctx $ updateVerifiedData ClientRole fdata
            _              -> return ()
        let encoded = encodeHandshake hs
        usingHState ctx $ do
            when (certVerifyHandshakeMaterial hs) $ addHandshakeMessage encoded
            when (finishHandshakeMaterial hs) $ updateHandshakeDigest encoded
    prepareRecord ctx (makeRecord pkt >>= engageRecord >>= encodeRecord)
writePacket ctx pkt = do
    d <- prepareRecord ctx (makeRecord pkt >>= engageRecord >>= encodeRecord)
    when (pkt == ChangeCipherSpec) $ switchTxEncryption ctx
    return d

engageAndEncode :: RecordM (Record Plaintext) -> RecordM ByteString
engageAndEncode record = record >>= engageRecord >>= encodeRecord

writePacketDTLS :: Context -> Packet -> IO (Either TLSError [ByteString])
writePacketDTLS ctx (Handshake hss') = do
    let mtu = ctxMTU ctx
    msgSeq <- ctxNextHsMsgSeq ctx (fromIntegral $ length hss')
    let hss = zipWith DtlsHandshake msgSeq hss'
    let updateCtx hs = do
        case hs of
            Finished fdata -> usingState_ ctx $ updateVerifiedData ClientRole fdata
            _              -> return ()
        -- https://tools.ietf.org/html/rfc6347#section-4.2.6 "in order
        -- to remove sensitivity to handshake message fragmentation,
        -- the Finished MAC MUST be computed as if each handshake
        -- message had been sent as a single fragment." - this is why 65535.
        let encodedForFinDgst = encodeHandshakeDTLS 65535 hs
        usingHState ctx $ do
            when (certVerifyHandshakeMaterial hs) $ mapM_ addHandshakeMessage encodedForFinDgst
            when (finishHandshakeMaterial hs) $ mapM_ updateHandshakeDigest encodedForFinDgst
    mapM_ updateCtx hss 
    prepareRecord ctx $ sequence $ map engageAndEncode $ makeHsRecordDTLS mtu hss
writePacketDTLS ctx pkt = do
    let mtu = ctxMTU ctx
    d <- prepareRecord ctx $ return <$> (engageAndEncode $ makeNonHsRecordDTLS mtu pkt)
    when (pkt == ChangeCipherSpec) $ switchTxEncryption ctx
    return d

-- before TLS 1.1, the block cipher IV is made of the residual of the previous block,
-- so we use cstIV as is, however in other case we generate an explicit IV
prepareRecord :: Context -> RecordM a -> IO (Either TLSError a)
prepareRecord ctx f = do
    ver     <- usingState_ ctx (getVersionWithDefault $ maximum $ supportedVersions $ ctxSupported ctx)
    txState <- readMVar $ ctxTxState ctx
    let sz = case stCipher txState of
                  Nothing     -> 0
                  Just cipher -> if hasRecordIV $ bulkF $ cipherBulk cipher
                                    then bulkIVSize $ cipherBulk cipher
                                    else 0 -- to not generate IV
    if hasExplicitBlockIV ver && sz > 0
        then do newIV <- getStateRNG ctx sz
                runTxState ctx (modify (setRecordIV newIV) >> f)
        else runTxState ctx f

switchTxEncryption :: Context -> IO ()
switchTxEncryption ctx = do
    tx  <- usingHState ctx (fromJust "tx-state" <$> gets hstPendingTxState)
    (ver, cc) <- usingState_ ctx $ do v <- getVersion
                                      c <- isClientContext
                                      return (v, c)
    liftIO $ modifyMVar_ (ctxTxState ctx) (\txprev -> return $ tx { stSeqNumber = nextEpoch $ stSeqNumber txprev })
    -- set empty packet counter measure if condition are met
    when (ver <= TLS10 && cc == ClientRole && isCBC tx && supportedEmptyPacket (ctxSupported ctx)) $ liftIO $ writeIORef (ctxNeedEmptyPacket ctx) True
  where isCBC tx = maybe False (\c -> bulkBlockSize (cipherBulk c) > 0) (stCipher tx)
