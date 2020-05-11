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
  , updateHandshake
  ) where

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Handshake.State
import Network.TLS.Imports
import Network.TLS.Packet
import Network.TLS.Parameters
import Network.TLS.Record
import Network.TLS.Record.Layer
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
encodePacket :: Monoid bytes
             => Context -> RecordLayer bytes -> Packet -> IO (Either TLSError bytes)
encodePacket ctx recordLayer pkt = do
    (ver, _) <- decideRecordVersion ctx
    let pt = packetType pkt
        mkRecord bs = Record pt ver (fragmentPlaintext bs)
        len = ctxFragmentSize ctx
    records <- map mkRecord <$> packetToFragments ctx len pkt
    bs <- fmap mconcat <$> forEitherM records (recordEncode recordLayer)
    when (pkt == ChangeCipherSpec) $ switchTxEncryption ctx
    return bs

-- Decompose handshake packets into fragments of the specified length.  AppData
-- packets are not fragmented here but by callers of sendPacket, so that the
-- empty-packet countermeasure may be applied to each fragment independently.
packetToFragments :: Context -> Maybe Int -> Packet -> IO [ByteString]
packetToFragments ctx len (Handshake hss)  =
    getChunks len . B.concat <$> mapM (updateHandshake ctx ClientRole) hss
packetToFragments _   _   (Alert a)        = return [encodeAlerts a]
packetToFragments _   _   ChangeCipherSpec = return [encodeChangeCipherSpec]
packetToFragments _   _   (AppData x)      = return [x]

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
