{-# LANGUAGE CPP #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- |
-- Module      : Network.TLS.IO
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.IO
    ( checkValid
    , sendPacket
    , sendPacket13
    , recvPacket
    , recvPacket13
    -- * Grouping multiple packets in the same flight
    , PacketFlightM
    , runPacketFlight
    , loadPacket13
    ) where

import Network.TLS.Context.Internal
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Record
import Network.TLS.Record.Types13
import Network.TLS.Record.Disengage13
import Network.TLS.Packet
import Network.TLS.Hooks
import Network.TLS.Sending
import Network.TLS.Sending13
import Network.TLS.Receiving
import Network.TLS.Imports
import Network.TLS.Receiving13
import Network.TLS.State
import qualified Data.ByteString as B

import Data.IORef
import Control.Monad.Reader
import Control.Exception (finally, throwIO)
import System.IO.Error (mkIOError, eofErrorType)

checkValid :: Context -> IO ()
checkValid ctx = do
    established <- ctxEstablished ctx
    when (established == NotEstablished) $ throwIO ConnectionNotEstablished
    eofed <- ctxEOF ctx
    when eofed $ throwIO $ mkIOError eofErrorType "data" Nothing Nothing

readExact :: Context -> Int -> IO (Either TLSError ByteString)
readExact ctx sz = do
    hdrbs <- contextRecv ctx sz
    if B.length hdrbs == sz
        then return $ Right hdrbs
        else do
            setEOF ctx
            return . Left $
                if B.null hdrbs
                    then Error_EOF
                    else Error_Packet ("partial packet: expecting " ++ show sz ++ " bytes, got: " ++ show (B.length hdrbs))



-- Read out the bytes necessary for Header deserialization.
-- This depends on version (5 bytes for TLS, plus 8 more bytes for DTLS).
readHeaderBytes :: Context -> IO (Either TLSError ByteString)
readHeaderBytes ctx = do
  eb <- readExact ctx 5
  case eb of
    Left _ -> return eb
    Right b -> let verMajor = b `B.index` 1
               in if verMajor /= 254 -- non DTLS record
                  then return eb
                  else liftM (b <>) <$> readExact ctx 8

-- | recvRecord receive a full TLS record (header + data), from the other side.
--
-- The record is disengaged from the record layer
recvRecord :: Bool    -- ^ flag to enable SSLv2 compat ClientHello reception
           -> Context -- ^ TLS context
           -> IO (Either TLSError (Record Plaintext))
recvRecord compatSSLv2 ctx
#ifdef SSLV2_COMPATIBLE
    | compatSSLv2 = readExact ctx 2 >>= either (return . Left) sslv2Header
#endif
    | otherwise = readHeaderBytes ctx >>= either (return . Left) (recvLengthE . decodeHeader)
        where recvLengthE = either (return . Left) recvLength

              recvLength header@(Header _ _ _ readlen)
                | readlen > 16384 + 2048 = return $ Left maximumSizeExceeded
                | otherwise              =
                    readExact ctx (fromIntegral readlen) >>=
                        either (return . Left) (getRecord header)
#ifdef SSLV2_COMPATIBLE
              sslv2Header header =
                if B.head header >= 0x80
                    then either (return . Left) recvDeprecatedLength $ decodeDeprecatedHeaderLength header
                    else readExact ctx 3 >>=
                            either (return . Left) (recvLengthE . decodeHeader . B.append header)

              recvDeprecatedLength readlen
                | readlen > 1024 * 4     = return $ Left maximumSizeExceeded
                | otherwise              = do
                    res <- readExact ctx (fromIntegral readlen)
                    case res of
                      Left e -> return $ Left e
                      Right content ->
                        either (return . Left) (`getRecord` content) $ decodeDeprecatedHeader readlen content
#endif
              maximumSizeExceeded = Error_Protocol ("record exceeding maximum size", True, RecordOverflow)
              getRecord :: Header -> ByteString -> IO (Either TLSError (Record Plaintext))
              getRecord header content = do
                    withLog ctx $ \logging -> loggingIORecv logging header content
                    runRxState ctx $ disengageRecord $ rawToRecord header (fragmentCiphertext content)

isCCS :: Record a -> Bool
isCCS (Record ProtocolType_ChangeCipherSpec _ _ _) = True
isCCS _                                            = False

-- Receive records and pass them through cache/replay window/reorder procedures (in case of DTLS)
recvRecordCacheAware :: Bool -> Context -> IO (Either TLSError (Record Plaintext))
recvRecordCacheAware sslv2 ctx = do
  mr <- ctxRecordCache ctx Nothing
  case mr of
    Just r -> return $ Right r
    Nothing -> do
      er <- recvRecord sslv2 ctx
      case er of
        Left _ -> return er
        Right r@(Record _ ver _ _) -> 
          if not $ isDTLS ver
          then return er
          else do
            mr' <- ctxRecordCache ctx $ Just r
            case mr' of
              Just r' -> return $ Right r'
              Nothing -> recvRecordCacheAware sslv2 ctx

-- | receive one packet from the context that contains 1 or
-- many messages (many only in case of handshake). if will returns a
-- TLSError if the packet is unexpected or malformed
recvPacket :: MonadIO m => Context -> m (Either TLSError Packet)
recvPacket ctx = liftIO $ do
    compatSSLv2 <- ctxHasSSLv2ClientHello ctx
    erecord     <- recvRecordCacheAware compatSSLv2 ctx
    case erecord of
        Left err     -> return $ Left err
        Right record -> do
            hrr <- usingState_ ctx getTLS13HRR
            if hrr && isCCS record then
                recvPacket ctx
              else do
                pktRecv <- processPacket ctx record
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

-- | Send one packet to the context
sendPacketTLS :: MonadIO m => Context -> Packet -> m ()
sendPacketTLS ctx pkt = do
    -- in ver <= TLS1.0, block ciphers using CBC are using CBC residue as IV, which can be guessed
    -- by an attacker. Hence, an empty packet is sent before a normal data packet, to
    -- prevent guessability.
    withEmptyPacket <- liftIO $ readIORef $ ctxNeedEmptyPacket ctx
    when (isNonNullAppData pkt && withEmptyPacket) $ sendPacket ctx $ AppData B.empty

    edataToSend <- liftIO $ do
                        withLog ctx $ \logging -> loggingPacketSent logging (show pkt)
                        writePacket ctx pkt
    case edataToSend of
        Left err         -> throwCore err
        Right dataToSend -> sendBytes ctx dataToSend
  where isNonNullAppData (AppData b) = not $ B.null b
        isNonNullAppData _           = False

sendPacketDTLS :: MonadIO m => Context -> Packet -> m ()
sendPacketDTLS ctx pkt = do
    edataToSend <- liftIO $ do
                        withLog ctx $ \logging -> loggingPacketSent logging (show pkt)
                        writePacketDTLS ctx pkt
    case edataToSend of
        Left err         -> throwCore err
        Right dataToSend -> mapM_ (sendBytes ctx) dataToSend

sendPacket :: MonadIO m => Context -> Packet -> m ()
sendPacket ctx pkt =
  if ctxIsDTLS ctx
  then sendPacketDTLS ctx pkt
  else sendPacketTLS ctx pkt


sendPacket13 :: MonadIO m => Context -> Packet13 -> m ()
sendPacket13 ctx pkt = writePacketBytes13 ctx pkt >>= sendBytes ctx

writePacketBytes13 :: MonadIO m => Context -> Packet13 -> m ByteString
writePacketBytes13 ctx pkt = do
    edataToSend <- liftIO $ do
                        withLog ctx $ \logging -> loggingPacketSent logging (show pkt)
                        writePacket13 ctx pkt
    either throwCore return edataToSend

sendBytes :: MonadIO m => Context -> ByteString -> m ()
sendBytes ctx dataToSend = liftIO $ do
    withLog ctx $ \logging -> loggingIOSent logging dataToSend
    contextSend ctx dataToSend

recvRecord13 :: Context
            -> IO (Either TLSError Record13)
recvRecord13 ctx = readExact ctx 5 >>= either (return . Left) (recvLengthE . decodeHeader)
  where recvLengthE = either (return . Left) recvLength
        recvLength header@(Header _ _ _ readlen)
          | readlen > 16384 + 2048 = return $ Left maximumSizeExceeded
          | otherwise              =
              readExact ctx (fromIntegral readlen) >>=
                 either (return . Left) (getRecord header)
        maximumSizeExceeded = Error_Protocol ("record exceeding maximum size", True, RecordOverflow)
        getRecord :: Header -> ByteString -> IO (Either TLSError Record13)
        getRecord header content = do
              liftIO $ withLog ctx $ \logging -> loggingIORecv logging header content
              runRxState ctx $ disengageRecord13 $ rawToRecord13 header content

recvPacket13 :: MonadIO m => Context -> m (Either TLSError Packet13)
recvPacket13 ctx = liftIO $ do
    erecord <- recvRecord13 ctx
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
            pkt <- processPacket13 ctx record
            case pkt of
                Right p -> withLog ctx $ \logging -> loggingPacketRecv logging $ show p
                _       -> return ()
            return pkt

-- | State monad used to group several packets together and send them on wire as
-- single flight.  When packets are loaded in the monad, they are logged
-- immediately, update the context digest and transcript, but actual sending is
-- deferred.  Packets are sent all at once when the monadic computation ends
-- (normal termination but also if interrupted by an exception).
newtype PacketFlightM a = PacketFlightM (ReaderT (IORef [ByteString]) IO a)
    deriving (Functor, Applicative, Monad, MonadIO)

runPacketFlight :: Context -> PacketFlightM a -> IO a
runPacketFlight ctx (PacketFlightM f) = do
    ref <- newIORef []
    finally (runReaderT f ref) $ do
        st <- readIORef ref
        unless (null st) $ sendBytes ctx $ B.concat $ reverse st

loadPacket13 :: Context -> Packet13 -> PacketFlightM ()
loadPacket13 ctx pkt = PacketFlightM $ do
    bs <- writePacketBytes13 ctx pkt
    ref <- ask
    liftIO $ modifyIORef ref (bs :)
