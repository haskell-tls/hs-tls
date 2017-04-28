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

import Control.Applicative
import Control.Monad.State.Strict
import Control.Concurrent.MVar
import Data.IORef

import Data.ByteString (ByteString)
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
writePacket :: Context -> Packet -> IO (Either TLSError ByteString)
writePacket ctx pkt@(Handshake hss) = do
    forM_ hss $ \hs -> do
        case hs of
            Finished fdata -> usingState_ ctx $ updateVerifiedData ClientRole fdata
            _              -> return ()
        let encoded = encodeHandshake hs
        usingHState ctx $ do
            when (certVerifyHandshakeMaterial hs) $ addHandshakeMessage encoded
            when (finishHandshakeTypeMaterial $ typeOfHandshake hs) $ updateHandshakeDigest encoded
    prepareRecord ctx (makeRecord pkt >>= engageRecord >>= encodeRecord)
writePacket ctx pkt = do
    d <- prepareRecord ctx (makeRecord pkt >>= engageRecord >>= encodeRecord)
    when (pkt == ChangeCipherSpec) $ switchTxEncryption ctx
    return d

-- before TLS 1.1, the block cipher IV is made of the residual of the previous block,
-- so we use cstIV as is, however in other case we generate an explicit IV
prepareRecord :: Context -> RecordM a -> IO (Either TLSError a)
prepareRecord ctx f = do
    ver     <- usingState_ ctx (getVersionWithDefault $ maximum $ supportedVersions $ ctxSupported ctx)
    txState <- readMVar $ ctxTxState ctx
    let sz = case stCipher $ txState of
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
    liftIO $ modifyMVar_ (ctxTxState ctx) (\_ -> return tx)
    -- set empty packet counter measure if condition are met
    when (ver <= TLS10 && cc == ClientRole && isCBC tx && supportedEmptyPacket (ctxSupported ctx)) $ liftIO $ writeIORef (ctxNeedEmptyPacket ctx) True
  where isCBC tx = maybe False (\c -> bulkBlockSize (cipherBulk c) > 0) (stCipher tx)
