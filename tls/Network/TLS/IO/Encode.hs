module Network.TLS.IO.Encode (
    encodePacket12,
    encodePacket13,
    updateTranscriptHash12,
    encodeUpdateTranscriptHash12,
    updateTranscriptHash13,
    encodeUpdateTranscriptHash13,
) where

import Control.Concurrent.MVar
import Control.Monad.State.Strict
import qualified Data.ByteString as B
import Data.IORef

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Handshake.State
import Network.TLS.Handshake.TranscriptHash
import Network.TLS.Imports
import Network.TLS.Packet
import Network.TLS.Packet13
import Network.TLS.Parameters
import Network.TLS.Record
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types (Role (..))
import Network.TLS.Util

-- | encodePacket transform a packet into marshalled data related to current state
-- and updating state on the go
encodePacket12
    :: Monoid bytes
    => Context
    -> RecordLayer bytes
    -> Packet
    -> IO (Either TLSError bytes)
encodePacket12 ctx recordLayer pkt = do
    (ver, _) <- decideRecordVersion ctx
    let pt = packetType pkt
        mkRecord bs = Record pt ver (fragmentPlaintext bs)
    mlen <- getPeerRecordLimit ctx
    records <- map mkRecord <$> packetToFragments12 ctx mlen pkt
    bs <- fmap mconcat <$> forEitherM records (recordEncode12 recordLayer ctx)
    when (pkt == ChangeCipherSpec) $ switchTxEncryption ctx
    return bs

-- Decompose handshake packets into fragments of the specified length.  AppData
-- packets are not fragmented here but by callers of sendPacket, so that the
-- empty-packet countermeasure may be applied to each fragment independently.
packetToFragments12 :: Context -> Maybe Int -> Packet -> IO [ByteString]
packetToFragments12 ctx mlen (Handshake hss _) =
    getChunks mlen . B.concat <$> mapM (encodeUpdateTranscriptHash12 ctx) hss
packetToFragments12 _ _ (Alert a) = return [encodeAlerts a]
packetToFragments12 _ _ ChangeCipherSpec = return [encodeChangeCipherSpec]
packetToFragments12 _ _ (AppData x) = return [x]

switchTxEncryption :: Context -> IO ()
switchTxEncryption ctx = do
    tx <- usingHState ctx (fromJust <$> gets hstPendingTxState)
    (ver, role) <- usingState_ ctx $ do
        v <- getVersion
        r <- getRole
        return (v, r)
    liftIO $ modifyMVar_ (ctxTxRecordState ctx) (\_ -> return tx)
    -- set empty packet counter measure if condition are met
    when
        ( ver <= TLS10
            && role == ClientRole
            && isCBC tx
            && supportedEmptyPacket (ctxSupported ctx)
        )
        $ liftIO
        $ writeIORef (ctxNeedEmptyPacket ctx) True
  where
    isCBC tx = maybe False (\c -> bulkBlockSize (cipherBulk c) > 0) (stCipher tx)

encodeUpdateTranscriptHash12 :: Context -> Handshake -> IO ByteString
encodeUpdateTranscriptHash12 ctx hs = do
    when (certVerifyHandshakeMaterial hs) $
        usingHState ctx $
            addHandshakeMessage encoded
    let label = show $ typeOfHandshake hs
    when (finishedHandshakeMaterial hs) $ updateTranscriptHash ctx label encoded
    when (isClientHello hs) $ do
        usingHState ctx $ do
            (ch, b) <- fromJust <$> getClientHello
            when (null b) $ setClientHello ch [encoded]
    return encoded
  where
    encoded = encodeHandshake hs
    isClientHello (ClientHello _) = True
    isClientHello _ = False

updateTranscriptHash12 :: Context -> HandshakeR -> IO ()
updateTranscriptHash12 ctx (hs, bss) = do
    when (certVerifyHandshakeMaterial hs) $
        usingHState ctx $
            mapM_ addHandshakeMessage bss
    let label = show $ typeOfHandshake hs
    when (finishedHandshakeMaterial hs) $ do
        mapM_ (updateTranscriptHash ctx label) bss

----------------------------------------------------------------

encodePacket13
    :: Monoid bytes
    => Context
    -> RecordLayer bytes
    -> Packet13
    -> IO (Either TLSError bytes)
encodePacket13 ctx recordLayer pkt = do
    let pt = contentType pkt
        mkRecord bs = Record pt TLS12 (fragmentPlaintext bs)
    mlen <- getPeerRecordLimit ctx
    records <- map mkRecord <$> packetToFragments13 ctx mlen pkt
    fmap mconcat <$> forEitherM records (recordEncode13 recordLayer ctx)

packetToFragments13 :: Context -> Maybe Int -> Packet13 -> IO [ByteString]
packetToFragments13 ctx mlen (Handshake13 hss _) =
    getChunks mlen . B.concat <$> mapM (encodeUpdateTranscriptHash13 ctx) hss
packetToFragments13 _ _ (Alert13 a) = return [encodeAlerts a]
packetToFragments13 _ _ (AppData13 x) = return [x]
packetToFragments13 _ _ ChangeCipherSpec13 = return [encodeChangeCipherSpec]

encodeUpdateTranscriptHash13 :: Context -> Handshake13 -> IO ByteString
encodeUpdateTranscriptHash13 ctx hs
    | isIgnored hs = return encoded
    | otherwise = do
        let label = show $ typeOfHandshake13 hs
        updateTranscriptHash ctx label encoded
        usingHState ctx $ addHandshakeMessage encoded
        return encoded
  where
    encoded = encodeHandshake13 hs

updateTranscriptHash13 :: Context -> Handshake13R -> IO ()
updateTranscriptHash13 ctx (hs, bss)
    | isIgnored hs = return ()
    | otherwise = do
        let label = show $ typeOfHandshake13 hs
        mapM_ (updateTranscriptHash ctx label) bss
        usingHState ctx $ mapM_ addHandshakeMessage bss

isIgnored :: Handshake13 -> Bool
isIgnored NewSessionTicket13{} = True
isIgnored KeyUpdate13{} = True
isIgnored _ = False
