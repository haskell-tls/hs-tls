{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RankNTypes #-}

module Network.TLS.IO (
    sendPacket12,
    sendPacket13,
    recvPacket12,
    recvPacket13,
    --
    isRecvComplete,
    checkValid,

    -- * Grouping multiple packets in the same flight
    PacketFlightM,
    runPacketFlight,
    loadPacket13,
) where

import Control.Exception (finally, throwIO)
import Control.Monad.Reader
import Control.Monad.State.Strict
import qualified Data.ByteString as B
import Data.IORef

import Network.TLS.Context.Internal
import Network.TLS.Hooks
import Network.TLS.IO.Decode
import Network.TLS.IO.Encode
import Network.TLS.Imports
import Network.TLS.Parameters
import Network.TLS.Record
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13

----------------------------------------------------------------

-- | Send one packet to the context
sendPacket12 :: Context -> Packet -> IO ()
sendPacket12 ctx@Context{ctxRecordLayer = recordLayer} pkt = do
    -- in ver <= TLS1.0, block ciphers using CBC are using CBC residue
    -- as IV, which can be guessed by an attacker. Hence, an empty
    -- packet is sent before a normal data packet, to prevent
    -- guessability.
    when (isNonNullAppData pkt) $ do
        withEmptyPacket <- readIORef $ ctxNeedEmptyPacket ctx
        when withEmptyPacket $
            writePacketBytes12 ctx recordLayer (AppData B.empty)
                >>= recordSendBytes recordLayer ctx

    writePacketBytes12 ctx recordLayer pkt >>= recordSendBytes recordLayer ctx
  where
    isNonNullAppData (AppData b) = not $ B.null b
    isNonNullAppData _ = False

writePacketBytes12
    :: Monoid bytes
    => Context
    -> RecordLayer bytes
    -> Packet
    -> IO bytes
writePacketBytes12 ctx recordLayer pkt = do
    withLog ctx $ \logging -> loggingPacketSent logging (show pkt)
    edataToSend <- encodePacket12 ctx recordLayer pkt
    either throwCore return edataToSend

----------------------------------------------------------------

sendPacket13 :: Context -> Packet13 -> IO ()
sendPacket13 ctx@Context{ctxRecordLayer = recordLayer} pkt =
    writePacketBytes13 ctx recordLayer pkt >>= recordSendBytes recordLayer ctx

writePacketBytes13
    :: Monoid bytes
    => Context
    -> RecordLayer bytes
    -> Packet13
    -> IO bytes
writePacketBytes13 ctx recordLayer pkt = do
    withLog ctx $ \logging -> loggingPacketSent logging (show pkt)
    edataToSend <- encodePacket13 ctx recordLayer pkt
    either throwCore return edataToSend

----------------------------------------------------------------

-- | receive one packet from the context that contains 1 or
-- many messages (many only in case of handshake). if will returns a
-- TLSError if the packet is unexpected or malformed
recvPacket12 :: Context -> IO (Either TLSError Packet)
recvPacket12 ctx@Context{ctxRecordLayer = recordLayer} = loop 0
  where
    lim = limitHandshakeFragment $ sharedLimit $ ctxShared ctx
    loop count
        | count > lim = do
            let err = Error_Packet "too many handshake fragment"
            logPacket ctx $ show err
            return $ Left err
    loop count = do
        hrr <- usingState_ ctx getTLS13HRR
        erecord <- recordRecv12 recordLayer ctx
        case erecord of
            Left err -> do
                logPacket ctx $ show err
                return $ Left err
            Right record
                | hrr && isCCS record -> loop (count + 1)
                | otherwise -> do
                    pktRecv <- decodePacket12 ctx record
                    if isEmptyHandshake pktRecv
                        then do
                            logPacket ctx "Handshake fragment"
                            -- When a handshake record is fragmented
                            -- we continue receiving in order to feed
                            -- stHandshakeRecordCont
                            loop (count + 1)
                        else case pktRecv of
                            Right (Handshake hss) -> do
                                pktRecv'@(Right pkt) <- ctxWithHooks ctx $ \hooks ->
                                    Right . Handshake <$> mapM (hookRecvHandshake hooks) hss
                                logPacket ctx $ show pkt
                                return pktRecv'
                            Right pkt -> do
                                logPacket ctx $ show pkt
                                return pktRecv
                            Left err -> do
                                logPacket ctx $ show err
                                return pktRecv

isCCS :: Record a -> Bool
isCCS (Record ProtocolType_ChangeCipherSpec _ _) = True
isCCS _ = False

isEmptyHandshake :: Either TLSError Packet -> Bool
isEmptyHandshake (Right (Handshake [])) = True
isEmptyHandshake _ = False

logPacket :: Context -> String -> IO ()
logPacket ctx msg = withLog ctx $ \logging -> loggingPacketRecv logging msg

----------------------------------------------------------------

recvPacket13 :: Context -> IO (Either TLSError Packet13)
recvPacket13 ctx@Context{ctxRecordLayer = recordLayer} = loop 0
  where
    lim = limitHandshakeFragment $ sharedLimit $ ctxShared ctx
    loop count
        | count > lim =
            return $ Left $ Error_Packet "too many handshake fragment"
    loop count = do
        erecord <- recordRecv13 recordLayer ctx
        case erecord of
            Left err@(Error_Protocol _ BadRecordMac) -> do
                -- If the server decides to reject RTT0 data but accepts RTT1
                -- data, the server should skip all records for RTT0 data.
                logPacket ctx $ show err
                established <- ctxEstablished ctx
                case established of
                    EarlyDataNotAllowed n
                        | n > 0 -> do
                            setEstablished ctx $ EarlyDataNotAllowed (n - 1)
                            loop (count + 1)
                    _ -> return $ Left err
            Left err -> do
                logPacket ctx $ show err
                return $ Left err
            Right record -> do
                pktRecv <- decodePacket13 ctx record
                if isEmptyHandshake13 pktRecv
                    then do
                        logPacket ctx "Handshake fragment"
                        -- When a handshake record is fragmented we
                        -- continue receiving in order to feed
                        -- stHandshakeRecordCont13
                        loop (count + 1)
                    else do
                        case pktRecv of
                            Right (Handshake13 hss) -> do
                                pktRecv'@(Right pkt) <- ctxWithHooks ctx $ \hooks ->
                                    Right . Handshake13 <$> mapM (hookRecvHandshake13 hooks) hss
                                logPacket ctx $ show pkt
                                return pktRecv'
                            Right pkt -> do
                                logPacket ctx $ show pkt
                                return pktRecv
                            Left err -> do
                                logPacket ctx $ show err
                                return pktRecv

isEmptyHandshake13 :: Either TLSError Packet13 -> Bool
isEmptyHandshake13 (Right (Handshake13 [])) = True
isEmptyHandshake13 _ = False

----------------------------------------------------------------

isRecvComplete :: Context -> IO Bool
isRecvComplete ctx = usingState_ ctx $ do
    cont12 <- gets stHandshakeRecordCont12
    cont13 <- gets stHandshakeRecordCont13
    return $ isNothing cont12 && isNothing cont13

checkValid :: Context -> IO ()
checkValid ctx = do
    established <- ctxEstablished ctx
    when (established == NotEstablished) $ throwIO ConnectionNotEstablished
    eofed <- ctxEOF ctx
    when eofed $ throwIO $ PostHandshake Error_EOF

----------------------------------------------------------------

type Builder b = [b] -> [b]

-- | State monad used to group several packets together and send them on wire as
-- single flight.  When packets are loaded in the monad, they are logged
-- immediately, update the context digest and transcript, but actual sending is
-- deferred.  Packets are sent all at once when the monadic computation ends
-- (normal termination but also if interrupted by an exception).
newtype PacketFlightM b a
    = PacketFlightM (ReaderT (RecordLayer b, IORef (Builder b)) IO a)
    deriving (Functor, Applicative, Monad, MonadFail, MonadIO)

runPacketFlight :: Context -> (forall b. Monoid b => PacketFlightM b a) -> IO a
runPacketFlight ctx@Context{ctxRecordLayer = recordLayer} (PacketFlightM f) = do
    ref <- newIORef id
    runReaderT f (recordLayer, ref) `finally` sendPendingFlight ctx recordLayer ref

sendPendingFlight
    :: Monoid b => Context -> RecordLayer b -> IORef (Builder b) -> IO ()
sendPendingFlight ctx recordLayer ref = do
    build <- readIORef ref
    let bss = build []
    unless (null bss) $ recordSendBytes recordLayer ctx $ mconcat bss

loadPacket13 :: Monoid b => Context -> Packet13 -> PacketFlightM b ()
loadPacket13 ctx pkt = PacketFlightM $ do
    (recordLayer, ref) <- ask
    liftIO $ do
        bs <- writePacketBytes13 ctx recordLayer pkt
        modifyIORef' ref (. (bs :))
