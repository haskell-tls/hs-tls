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
    encodePacket
  , encodeRecord
  , updateHandshake
  ) where

import Network.TLS.Cap
import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Handshake.State
import Network.TLS.Imports
import Network.TLS.Packet
import Network.TLS.Parameters
import Network.TLS.Record
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Types (Role(..))
import Network.TLS.Util

import Control.Concurrent.MVar
import Control.Monad.State.Strict
import qualified Data.ByteString as B
import Data.IORef

-- | encodePacket transform a packet into marshalled data related to current state
-- and updating state on the go
encodePacket :: Context -> Packet -> IO (Either TLSError ByteString)
encodePacket ctx pkt = do
    Right ver <- runTxState ctx getRecordVersion
    let pt = packetType pkt
        mkRecord bs = Record pt ver (fragmentPlaintext bs)
    records <- map mkRecord <$> packetToFragments ctx 16384 pkt
    bs <- fmap B.concat <$> forEitherM records (runEncodeRecord ctx)
    when (pkt == ChangeCipherSpec) $ switchTxEncryption ctx
    return bs

-- Decompose handshake packets into fragments of the specified length.  AppData
-- packets are not fragmented here but by callers of sendPacket, so that the
-- empty-packet countermeasure may be applied to each fragment independently.
packetToFragments :: Context -> Int -> Packet -> IO [ByteString]
packetToFragments ctx len pkt  = encodePacketContent pkt
  where
    encodePacketContent (Handshake hss)    =
        getChunks len . B.concat <$> mapM (updateHandshake ctx ClientRole) hss
    encodePacketContent (Alert a)          = return [encodeAlerts a]
    encodePacketContent  ChangeCipherSpec  = return [encodeChangeCipherSpec]
    encodePacketContent (AppData x)        = return [x]

-- before TLS 1.1, the block cipher IV is made of the residual of the previous block,
-- so we use cstIV as is, however in other case we generate an explicit IV
runEncodeRecord :: Context -> Record Plaintext -> IO (Either TLSError ByteString)
runEncodeRecord ctx record = do
    ver     <- usingState_ ctx (getVersionWithDefault $ maximum $ supportedVersions $ ctxSupported ctx)
    txState <- readMVar $ ctxTxState ctx
    let sz = case stCipher txState of
                  Nothing     -> 0
                  Just cipher
                    | hasRecordIV $ bulkF $ cipherBulk cipher -> bulkIVSize $ cipherBulk cipher
                    | otherwise -> 0 -- to not generate IV
    if hasExplicitBlockIV ver && sz > 0
        then do newIV <- getStateRNG ctx sz
                runTxState ctx (modify (setRecordIV newIV) >> encodeRecord record)
        else runTxState ctx $ encodeRecord record

encodeRecord :: Record Plaintext -> RecordM ByteString
encodeRecord record = do
    erecord <- engageRecord record
    let (hdr, content) = recordToRaw erecord
    return $ B.concat [ encodeHeader hdr, content ]

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

updateHandshake :: Context -> Role -> Handshake -> IO ByteString
updateHandshake ctx role hs = do
    case hs of
        Finished fdata -> usingState_ ctx $ updateVerifiedData role fdata
        _              -> return ()
    usingHState ctx $ do
        when (certVerifyHandshakeMaterial hs) $ addHandshakeMessage encoded
        when (finishHandshakeTypeMaterial $ typeOfHandshake hs) $ updateHandshakeDigest encoded
    return encoded
  where
    encoded = encodeHandshake hs
