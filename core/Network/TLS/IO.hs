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
    , runPacketNonFlight
    , loadPacket13
    ) where

import Control.Exception (finally, throwIO)
import Control.Monad.Reader
import Control.Monad.State.Strict
import qualified Data.ByteString as B
import Data.IORef
import System.IO.Error (mkIOError, eofErrorType)

import Network.TLS.Context.Internal
import Network.TLS.ErrT
import Network.TLS.Hooks
import Network.TLS.Imports
import Network.TLS.Packet
import Network.TLS.Receiving
import Network.TLS.Receiving13
import Network.TLS.Record
import qualified Network.TLS.Record.Layer as RL
import Network.TLS.Sending
import Network.TLS.Sending13
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13

----------------------------------------------------------------

-- | Send one packet to the context
sendPacket :: Context -> Packet -> IO ()
sendPacket ctx pkt = do
    -- in ver <= TLS1.0, block ciphers using CBC are using CBC residue as IV, which can be guessed
    -- by an attacker. Hence, an empty packet is sent before a normal data packet, to
    -- prevent guessability.
    when (isNonNullAppData pkt) $ do
        withEmptyPacket <- liftIO $ readIORef $ ctxNeedEmptyPacket ctx
        when withEmptyPacket $
            writePacketBytes ctx (AppData B.empty) >>= contextSendBytes ctx

    writePacketBytes ctx pkt >>= contextSendBytes ctx
  where isNonNullAppData (AppData b) = not $ B.null b
        isNonNullAppData _           = False

writePacketBytes :: MonadIO m => Context -> Packet -> m ByteString
writePacketBytes ctx pkt = do
    edataToSend <- liftIO $ do
                        withLog ctx $ \logging -> loggingPacketSent logging (show pkt)
                        encodePacket ctx pkt
    either throwCore return edataToSend

----------------------------------------------------------------

sendPacket13 :: Context -> Packet13 -> IO ()
sendPacket13 ctx pkt = writePacketBytes13 ctx pkt >>= contextSendBytes ctx

writePacketBytes13 :: MonadIO m => Context -> Packet13 -> m ByteString
writePacketBytes13 ctx pkt = do
    edataToSend <- liftIO $ do
                        withLog ctx $ \logging -> loggingPacketSent logging (show pkt)
                        encodePacket13 ctx pkt
    either throwCore return edataToSend

sendBytes :: MonadIO m => Context -> ByteString -> m ()
sendBytes ctx dataToSend = liftIO $ do
    withLog ctx $ \logging -> loggingIOSent logging dataToSend
    contextSend ctx dataToSend

----------------------------------------------------------------

exceeds :: Integral ty => Context -> Int -> ty -> Bool
exceeds ctx overhead actual =
    case ctxFragmentSize ctx of
        Nothing -> False
        Just sz -> fromIntegral actual > sz + overhead

getRecord :: Context -> Int -> Header -> ByteString -> IO (Either TLSError (Record Plaintext))
getRecord ctx appDataOverhead header@(Header pt _ _) content = do
    withLog ctx $ \logging -> loggingIORecv logging header content
    runRxState ctx $ do
        r <- decodeRecordM header content
        let Record _ _ fragment = r
        when (exceeds ctx overhead $ B.length (fragmentGetBytes fragment)) $
            throwError contentSizeExceeded
        return r
  where overhead = if pt == ProtocolType_AppData then appDataOverhead else 0


contentSizeExceeded :: TLSError
contentSizeExceeded = Error_Protocol ("record content exceeding maximum size", True, RecordOverflow)

----------------------------------------------------------------
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
    erecord     <- contextRecvRecord ctx compatSSLv2 appDataOverhead
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

-- | recvRecord receive a full TLS record (header + data), from the other side.
--
-- The record is disengaged from the record layer
recvRecord :: Bool    -- ^ flag to enable SSLv2 compat ClientHello reception
           -> Int     -- ^ number of AppData bytes to accept above normal maximum size
           -> Context -- ^ TLS context
           -> IO (Either TLSError (Record Plaintext))
recvRecord compatSSLv2 appDataOverhead ctx
#ifdef SSLV2_COMPATIBLE
    | compatSSLv2 = readExactBytes ctx 2 >>= either (return . Left) sslv2Header
#endif
    | otherwise = readExactBytes ctx 5 >>= either (return . Left) (recvLengthE . decodeHeader)

        where recvLengthE = either (return . Left) recvLength

              recvLength header@(Header _ _ readlen)
                | exceeds ctx 2048 readlen = return $ Left maximumSizeExceeded
                | otherwise                =
                    readExactBytes ctx (fromIntegral readlen) >>=
                        either (return . Left) (getRecord ctx appDataOverhead header)
#ifdef SSLV2_COMPATIBLE
              sslv2Header header =
                if B.head header >= 0x80
                    then either (return . Left) recvDeprecatedLength $ decodeDeprecatedHeaderLength header
                    else readExactBytes ctx 3 >>=
                            either (return . Left) (recvLengthE . decodeHeader . B.append header)

              recvDeprecatedLength readlen
                | readlen > 1024 * 4     = return $ Left maximumSizeExceeded
                | otherwise              = do
                    res <- readExactBytes ctx (fromIntegral readlen)
                    case res of
                      Left e -> return $ Left e
                      Right content ->
                        let hdr = decodeDeprecatedHeader readlen (B.take 3 content)
                         in either (return . Left) (\h -> getRecord ctx appDataOverhead h content) hdr
#endif

isCCS :: Record a -> Bool
isCCS (Record ProtocolType_ChangeCipherSpec _ _) = True
isCCS _                                          = False

isEmptyHandshake :: Either TLSError Packet -> Bool
isEmptyHandshake (Right (Handshake [])) = True
isEmptyHandshake _                      = False

----------------------------------------------------------------

recvPacket13 :: MonadIO m => Context -> m (Either TLSError Packet13)
recvPacket13 ctx = liftIO $ do
    erecord <- contextRecvRecord13 ctx
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

recvRecord13 :: Context
            -> IO (Either TLSError (Record Plaintext))
recvRecord13 ctx = readExactBytes ctx 5 >>= either (return . Left) (recvLengthE . decodeHeader)
  where recvLengthE = either (return . Left) recvLength
        recvLength header@(Header _ _ readlen)
          | exceeds ctx 256 readlen = return $ Left maximumSizeExceeded
          | otherwise               =
              readExactBytes ctx (fromIntegral readlen) >>=
                 either (return . Left) (getRecord ctx 0 header)

isEmptyHandshake13 :: Either TLSError Packet13 -> Bool
isEmptyHandshake13 (Right (Handshake13 [])) = True
isEmptyHandshake13 _                        = False

----------------------------------------------------------------
-- Common for receiving

maximumSizeExceeded :: TLSError
maximumSizeExceeded = Error_Protocol ("record exceeding maximum size", True, RecordOverflow)

readExactBytes :: Context -> Int -> IO (Either TLSError ByteString)
readExactBytes ctx sz = do
    hdrbs <- contextRecv ctx sz
    if B.length hdrbs == sz
        then return $ Right hdrbs
        else do
            setEOF ctx
            return . Left $
                if B.null hdrbs
                    then Error_EOF
                    else Error_Packet ("partial packet: expecting " ++ show sz ++ " bytes, got: " ++ show (B.length hdrbs))

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

type Builder = [ByteString] -> [ByteString]

-- | State monad used to group several packets together and send them on wire as
-- single flight.  When packets are loaded in the monad, they are logged
-- immediately, update the context digest and transcript, but actual sending is
-- deferred.  Packets are sent all at once when the monadic computation ends
-- (normal termination but also if interrupted by an exception).
newtype PacketFlightM a = PacketFlightM (ReaderT (IORef Builder) IO a)
    deriving (Functor, Applicative, Monad, MonadFail, MonadIO)

runPacketFlight :: Context -> [ByteString] -> PacketFlightM a -> IO a
runPacketFlight ctx bss0 (PacketFlightM f) = do
    ref <- newIORef id
    finally (runReaderT f ref) $ do
        build <- readIORef ref
        let bss = bss0 ++ build []
        unless (null bss) $ contextSendBytes ctx $ B.concat bss

runPacketNonFlight :: Context -> PacketFlightM () -> IO [ByteString]
runPacketNonFlight ctx (PacketFlightM f) = do
    ref <- newIORef id
    runReaderT f ref
    build <- readIORef ref
    let bss = build []
    case ctxRecordLayer ctx of
      Nothing -> return bss
      Just rl -> do
          RL.sendBytes rl $ B.concat bss
          return []

loadPacket13 :: Context -> Packet13 -> PacketFlightM ()
loadPacket13 ctx pkt = PacketFlightM $ do
    bs <- writePacketBytes13 ctx pkt
    ref <- ask
    liftIO $ modifyIORef ref (. (bs :))

----------------------------------------------------------------

contextSendBytes :: Context -> ByteString -> IO ()
contextSendBytes ctx = case ctxRecordLayer ctx of
  Nothing -> sendBytes ctx
  Just rl -> RL.sendBytes rl

contextRecvRecord :: Context -> Bool -> Int -> IO (Either TLSError (Record Plaintext))
contextRecvRecord ctx compatSSLv2 appDataOverhead = case ctxRecordLayer ctx of
  Nothing -> recvRecord compatSSLv2 appDataOverhead ctx
  Just rl -> RL.recvRecord rl

contextRecvRecord13 :: Context -> IO (Either TLSError (Record Plaintext))
contextRecvRecord13 ctx = case ctxRecordLayer ctx of
  Nothing -> recvRecord13 ctx
  Just rl -> RL.recvRecord rl
