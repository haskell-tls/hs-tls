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
import Network.TLS.ErrT
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Record
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

getRecord :: Context -> Int -> Header -> ByteString -> IO (Either TLSError (Record Plaintext))
getRecord ctx appDataOverhead header@(Header pt _ _) content = do
    withLog ctx $ \logging -> loggingIORecv logging header content
    runRxState ctx $ do
        r <- disengageRecord $ rawToRecord header (fragmentCiphertext content)
        let Record _ _ fragment = r
        when (B.length (fragmentGetBytes fragment) > 16384 + overhead) $
            throwError contentSizeExceeded
        return r
  where overhead = if pt == ProtocolType_AppData then appDataOverhead else 0

contentSizeExceeded :: TLSError
contentSizeExceeded = Error_Protocol ("record content exceeding maximum size", True, RecordOverflow)

maximumSizeExceeded :: TLSError
maximumSizeExceeded = Error_Protocol ("record exceeding maximum size", True, RecordOverflow)

-- | recvRecord receive a full TLS record (header + data), from the other side.
--
-- The record is disengaged from the record layer
recvRecord :: Bool    -- ^ flag to enable SSLv2 compat ClientHello reception
           -> Int     -- ^ number of AppData bytes to accept above normal maximum size
           -> Context -- ^ TLS context
           -> IO (Either TLSError (Record Plaintext))
recvRecord compatSSLv2 appDataOverhead ctx
#ifdef SSLV2_COMPATIBLE
    | compatSSLv2 = readExact ctx 2 >>= either (return . Left) sslv2Header
#endif
    | otherwise = readExact ctx 5 >>= either (return . Left) (recvLengthE . decodeHeader)

        where recvLengthE = either (return . Left) recvLength

              recvLength header@(Header _ _ readlen)
                | readlen > 16384 + 2048 = return $ Left maximumSizeExceeded
                | otherwise              =
                    readExact ctx (fromIntegral readlen) >>=
                        either (return . Left) (getRecord ctx appDataOverhead header)
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
                        either (return . Left) (\h -> getRecord ctx appDataOverhead h content) $ decodeDeprecatedHeader readlen content
#endif

isCCS :: Record a -> Bool
isCCS (Record ProtocolType_ChangeCipherSpec _ _) = True
isCCS _                                          = False

-- | receive one packet from the context that contains 1 or
-- many messages (many only in case of handshake). if will returns a
-- TLSError if the packet is unexpected or malformed
recvPacket :: MonadIO m => Context -> m (Either TLSError Packet)
recvPacket ctx = liftIO $ do
    compatSSLv2 <- ctxHasSSLv2ClientHello ctx
    hrr         <- usingState_ ctx getTLS13HRR
    -- When a client sends 0-RTT data to a server which rejects and sends a HRR,
    -- the server will not decrypt AppData segments.  The server needs to accept
    -- AppData with maximum size 2^14 + 256.  In all other scenarios and record
    -- types the maximum size is 2^14.
    let appDataOverhead = if hrr then 256 else 0
    erecord     <- recvRecord compatSSLv2 appDataOverhead ctx
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

isEmptyHandshake :: Either TLSError Packet -> Bool
isEmptyHandshake (Right (Handshake [])) = True
isEmptyHandshake _                      = False

-- | Send one packet to the context
sendPacket :: MonadIO m => Context -> Packet -> m ()
sendPacket ctx pkt = do
    -- in ver <= TLS1.0, block ciphers using CBC are using CBC residue as IV, which can be guessed
    -- by an attacker. Hence, an empty packet is sent before a normal data packet, to
    -- prevent guessability.
    when (isNonNullAppData pkt) $ do
        withEmptyPacket <- liftIO $ readIORef $ ctxNeedEmptyPacket ctx
        when withEmptyPacket $
            writePacketBytes ctx (AppData B.empty) >>= sendBytes ctx

    writePacketBytes ctx pkt >>= sendBytes ctx
  where isNonNullAppData (AppData b) = not $ B.null b
        isNonNullAppData _           = False

writePacketBytes :: MonadIO m => Context -> Packet -> m ByteString
writePacketBytes ctx pkt = do
    edataToSend <- liftIO $ do
                        withLog ctx $ \logging -> loggingPacketSent logging (show pkt)
                        writePacket ctx pkt
    either throwCore return edataToSend

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
            -> IO (Either TLSError (Record Plaintext))
recvRecord13 ctx = readExact ctx 5 >>= either (return . Left) (recvLengthE . decodeHeader)
  where recvLengthE = either (return . Left) recvLength
        recvLength header@(Header _ _ readlen)
          | readlen > 16384 + 256  = return $ Left maximumSizeExceeded
          | otherwise              =
              readExact ctx (fromIntegral readlen) >>=
                 either (return . Left) (getRecord ctx 0 header)

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
            if isEmptyHandshake13 pkt then
                -- When a handshake record is fragmented we continue receiving
                -- in order to feed stHandshakeRecordCont13
                recvPacket13 ctx
              else do
                case pkt of
                    Right p -> withLog ctx $ \logging -> loggingPacketRecv logging $ show p
                    _       -> return ()
                return pkt

isEmptyHandshake13 :: Either TLSError Packet13 -> Bool
isEmptyHandshake13 (Right (Handshake13 [])) = True
isEmptyHandshake13 _                        = False

-- | State monad used to group several packets together and send them on wire as
-- single flight.  When packets are loaded in the monad, they are logged
-- immediately, update the context digest and transcript, but actual sending is
-- deferred.  Packets are sent all at once when the monadic computation ends
-- (normal termination but also if interrupted by an exception).
newtype PacketFlightM a = PacketFlightM (ReaderT (IORef [ByteString]) IO a)
    deriving (Functor, Applicative, Monad, MonadFail, MonadIO)

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
