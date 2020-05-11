{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RankNTypes #-}
-- |
-- Module      : Network.TLS.IO
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.IO
    ( sendPacket
    , sendPacket13
    , recvPacket
    , recvPacket13
    --
    , isRecvComplete
    , checkValid
    -- * Grouping multiple packets in the same flight
    , PacketFlightM
    , runPacketFlight
    , loadPacket13
    ) where

import Control.Exception (finally, throwIO)
import Control.Monad.Reader
import Control.Monad.State.Strict
import qualified Data.ByteString as B
import Data.IORef
import System.IO.Error (mkIOError, eofErrorType)

import Network.TLS.Context.Internal
import Network.TLS.Hooks
import Network.TLS.Imports
import Network.TLS.Receiving
import Network.TLS.Record
import Network.TLS.Record.Layer
import Network.TLS.Sending
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13

----------------------------------------------------------------

-- | Send one packet to the context
sendPacket :: Context -> Packet -> IO ()
sendPacket ctx@Context{ctxRecordLayer = recordLayer} pkt = do
    -- in ver <= TLS1.0, block ciphers using CBC are using CBC residue as IV, which can be guessed
    -- by an attacker. Hence, an empty packet is sent before a normal data packet, to
    -- prevent guessability.
    when (isNonNullAppData pkt) $ do
        withEmptyPacket <- readIORef $ ctxNeedEmptyPacket ctx
        when withEmptyPacket $
            writePacketBytes ctx recordLayer (AppData B.empty) >>=
                recordSendBytes recordLayer

    writePacketBytes ctx recordLayer pkt >>= recordSendBytes recordLayer
  where isNonNullAppData (AppData b) = not $ B.null b
        isNonNullAppData _           = False

writePacketBytes :: Monoid bytes
                 => Context -> RecordLayer bytes -> Packet -> IO bytes
writePacketBytes ctx recordLayer pkt = do
    withLog ctx $ \logging -> loggingPacketSent logging (show pkt)
    edataToSend <- encodePacket ctx recordLayer pkt
    either throwCore return edataToSend

----------------------------------------------------------------

sendPacket13 :: Context -> Packet13 -> IO ()
sendPacket13 ctx@Context{ctxRecordLayer = recordLayer} pkt =
    writePacketBytes13 ctx recordLayer pkt >>= recordSendBytes recordLayer

writePacketBytes13 :: Monoid bytes
                   => Context -> RecordLayer bytes -> Packet13 -> IO bytes
writePacketBytes13 ctx recordLayer pkt = do
    withLog ctx $ \logging -> loggingPacketSent logging (show pkt)
    edataToSend <- encodePacket13 ctx recordLayer pkt
    either throwCore return edataToSend

----------------------------------------------------------------
-- | receive one packet from the context that contains 1 or
-- many messages (many only in case of handshake). if will returns a
-- TLSError if the packet is unexpected or malformed
recvPacket :: Context -> IO (Either TLSError Packet)
recvPacket ctx@Context{ctxRecordLayer = recordLayer} = do
    compatSSLv2 <- ctxHasSSLv2ClientHello ctx
    hrr         <- usingState_ ctx getTLS13HRR
    -- When a client sends 0-RTT data to a server which rejects and sends a HRR,
    -- the server will not decrypt AppData segments.  The server needs to accept
    -- AppData with maximum size 2^14 + 256.  In all other scenarios and record
    -- types the maximum size is 2^14.
    let appDataOverhead = if hrr then 256 else 0
    erecord <- recordRecv recordLayer compatSSLv2 appDataOverhead
    case erecord of
        Left err     -> return $ Left err
        Right record ->
            if hrr && isCCS record then
                recvPacket ctx
              else do
                pktRecv <- processPacket ctx record
                if isEmptyHandshake pktRecv then
                    -- When a handshake record is fragmented we continue
                    -- receiving in order to feed stHandshakeRecordCont
                    recvPacket ctx
                  else do
                    pkt <- case pktRecv of
                            Right (Handshake hss) ->
                                ctxWithHooks ctx $ \hooks ->
                                    Right . Handshake <$> mapM (hookRecvHandshake hooks) hss
                            _                     -> return pktRecv
                    case pkt of
                        Right p -> withLog ctx $ \logging -> loggingPacketRecv logging $ show p
                        _       -> return ()
                    when compatSSLv2 $ ctxDisableSSLv2ClientHello ctx
                    return pkt

isCCS :: Record a -> Bool
isCCS (Record ProtocolType_ChangeCipherSpec _ _) = True
isCCS _                                          = False

isEmptyHandshake :: Either TLSError Packet -> Bool
isEmptyHandshake (Right (Handshake [])) = True
isEmptyHandshake _                      = False

----------------------------------------------------------------

recvPacket13 :: Context -> IO (Either TLSError Packet13)
recvPacket13 ctx@Context{ctxRecordLayer = recordLayer} = do
    erecord <- recordRecv13 recordLayer
    case erecord of
        Left err@(Error_Protocol (_, True, BadRecordMac)) -> do
            -- If the server decides to reject RTT0 data but accepts RTT1
            -- data, the server should skip all records for RTT0 data.
            established <- ctxEstablished ctx
            case established of
                EarlyDataNotAllowed n
                    | n > 0 -> do setEstablished ctx $ EarlyDataNotAllowed (n - 1)
                                  recvPacket13 ctx
                _           -> return $ Left err
        Left err      -> return $ Left err
        Right record -> do
            pktRecv <- processPacket13 ctx record
            if isEmptyHandshake13 pktRecv then
                -- When a handshake record is fragmented we continue receiving
                -- in order to feed stHandshakeRecordCont13
                recvPacket13 ctx
              else do
                pkt <- case pktRecv of
                        Right (Handshake13 hss) ->
                            ctxWithHooks ctx $ \hooks ->
                                Right . Handshake13 <$> mapM (hookRecvHandshake13 hooks) hss
                        _                       -> return pktRecv
                case pkt of
                    Right p -> withLog ctx $ \logging -> loggingPacketRecv logging $ show p
                    _       -> return ()
                return pkt

isEmptyHandshake13 :: Either TLSError Packet13 -> Bool
isEmptyHandshake13 (Right (Handshake13 [])) = True
isEmptyHandshake13 _                        = False

----------------------------------------------------------------

isRecvComplete :: Context -> IO Bool
isRecvComplete ctx = usingState_ ctx $ do
    cont <- gets stHandshakeRecordCont
    cont13 <- gets stHandshakeRecordCont13
    return $! isNothing cont && isNothing cont13

checkValid :: Context -> IO ()
checkValid ctx = do
    established <- ctxEstablished ctx
    when (established == NotEstablished) $ throwIO ConnectionNotEstablished
    eofed <- ctxEOF ctx
    when eofed $ throwIO $ mkIOError eofErrorType "data" Nothing Nothing

----------------------------------------------------------------

type Builder b = [b] -> [b]

-- | State monad used to group several packets together and send them on wire as
-- single flight.  When packets are loaded in the monad, they are logged
-- immediately, update the context digest and transcript, but actual sending is
-- deferred.  Packets are sent all at once when the monadic computation ends
-- (normal termination but also if interrupted by an exception).
newtype PacketFlightM b a = PacketFlightM (ReaderT (RecordLayer b, IORef (Builder b)) IO a)
    deriving (Functor, Applicative, Monad, MonadFail, MonadIO)

runPacketFlight :: Context -> (forall b . Monoid b => PacketFlightM b a) -> IO a
runPacketFlight Context{ctxRecordLayer = recordLayer} (PacketFlightM f) = do
    ref <- newIORef id
    runReaderT f (recordLayer, ref) `finally` sendPendingFlight recordLayer ref

sendPendingFlight :: Monoid b => RecordLayer b -> IORef (Builder b) -> IO ()
sendPendingFlight recordLayer ref = do
    build <- readIORef ref
    let bss = build []
    unless (null bss) $ recordSendBytes recordLayer $ mconcat bss

loadPacket13 :: Monoid b => Context -> Packet13 -> PacketFlightM b ()
loadPacket13 ctx pkt = PacketFlightM $ do
    (recordLayer, ref) <- ask
    liftIO $ do
        bs <- writePacketBytes13 ctx recordLayer pkt
        modifyIORef ref (. (bs :))
