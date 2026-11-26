{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_HADDOCK hide #-}

module Network.TLS.Core (
    -- * Internal packet sending and receiving
    sendPacket12,
    recvPacket12,

    -- * Initialisation and Termination of context
    bye,
    byeWith,
    handshake,
    handshakeWith,

    -- * Application Layer Protocol Negotiation
    getNegotiatedProtocol,

    -- * Server Name Indication
    getClientSNI,

    -- * High level API
    sendData,
    sendDataWith,
    recvData,
    recvDataWith,
    recvData',
    closeNotifyReceived,
    updateKey,
    KeyUpdateRequest (..),
    requestCertificate,
    requestCertificateAsync,
    PHAResult (..),
) where

import Control.Concurrent (forkIO)
import Control.Concurrent.STM
import qualified Control.Exception as E
import Control.Monad.State.Strict
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as L
import Data.IORef
import GHC.IO.Exception (IOErrorType (..), IOException (..))

import Network.TLS.Context
import Network.TLS.Context.Internal (
    GaveUp (..),
    GiveUp (..),
    PHAResult (..),
    ctxTxBroken,
    gaveUpSending,
    incrementTLS13KeyUpdateCount,
    resetTLS13KeyUpdateCount,
    wakePHA,
    withRWLockGivingUp,
    withReadLockGivingUp,
    withRxGiveUp,
    withTxGiveUp,
    withWriteLockGivingUp,
 )
import Network.TLS.Extension
import Network.TLS.Handshake
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Server
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.Handshake.TranscriptHash
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.Parameters
import Network.TLS.PostHandshake
import Network.TLS.Session
import Network.TLS.State (getRole, getSession)
import qualified Network.TLS.State as S
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types (
    Bulk (..),
    Cipher (..),
    HostName,
    Millisecond,
    Role (..),
 )
import Network.TLS.Util (catchException, mapChunks_)

-- | Handshake for a new TLS connection.
-- This is to be called at the beginning of a connection, and during renegotiation.
-- Don't use this function as the acquire resource of 'Control.Exception.bracket'.
handshake :: MonadIO m => Context -> m ()
handshake ctx = liftIO $ do
    handshake_ ctx
    -- Trying to receive an alert of client authentication failure
    authFailureExpected ctx >>= \expected -> when expected $ waitAuthFailure ctx

-- | 'handshake' which gives up once the 'STM' action succeeds, also while
-- waiting for the locks or in a send.  After 'Left', the context cannot be
-- used.  With a backend which can neither give up on a receive nor on a
-- send, only the wait for the locks is given up on.
--
-- @since 2.6.4
handshakeWith :: MonadIO m => Context -> STM a -> m (Either a ())
handshakeWith ctx giveUp = liftIO $ do
    (giveUp', given) <- recording giveUp
    r <-
        E.try $
            withRWLockGivingUp ctx giveUp $
                withTxGiveUp ctx giveUp' $
                    withRxGiveUp ctx (GiveUp giveUp' giveUp') $
                        handshakeLocked ctx
    case r of
        Left e -> given >>= maybe (E.throwIO (e :: E.SomeException)) (return . Left)
        Right (Left a) -> return $ Left a
        Right (Right ()) -> do
            expected <- authFailureExpected ctx
            if not expected
                then return $ Right ()
                else case ctxBackendRecvWith ctx of
                    Nothing -> Right <$> waitAuthFailure ctx
                    Just _ -> waitAuthFailureGivingUp ctx giveUp' given

-- | Recording what the 'STM' action gave, for one which has given up.
recording :: STM a -> IO (STM (), IO (Maybe a))
recording giveUp = do
    var <- newTVarIO Nothing
    return (giveUp >>= writeTVar var . Just, readTVarIO var)

authFailureExpected :: Context -> IO Bool
authFailureExpected ctx = do
    role <- usingState_ ctx getRole
    tls13 <- tls13orLater ctx
    sentClientCert <- tls13stSentClientCert <$> getTLS13State ctx
    return $ role == ClientRole && tls13 && sentClientCert

-- | Waiting 'rtt' for an alert of client authentication failure.
waitAuthFailure :: Context -> IO ()
waitAuthFailure ctx = do
    rtt <- getRTT ctx
    -- We are only willing to wait 'rtt' for the alert, but a receive
    -- must not be abandoned once it has started.  Records are read
    -- length-prefixed and the record layer keeps no receive buffer, so
    -- an aborted receive loses the bytes it has already taken off the
    -- transport and leaves the stream positioned inside a record.
    -- Every later read is then misframed, and the connection is dead
    -- with a spurious protocol error.
    --
    -- So the receive runs in its own thread and we stop waiting for it
    -- rather than interrupting it.  It holds the read lock, which keeps
    -- it the only reader and makes the next receive wait for it to
    -- finish; its outcome is left in 'tls13stPendingRecv' for that
    -- receive to pick up.
    done <- newEmptyTMVarIO
    void $ forkIO $ withReadLock ctx $ do
        r <- E.try $ recvData13 ctx
        modifyTLS13State ctx $ \st ->
            st
                { tls13stPendingRecv = case r of
                    Right dat -> PendingRecvData dat
                    Left err -> PendingRecvError err
                }
        atomically $ putTMVar done ()
    late <- registerDelay rtt
    arrived <-
        atomically $
            (Just <$> takeTMVar done) `orElse` (Nothing <$ (readTVar late >>= check))
    -- Still report the authentication failure from 'handshake' itself
    -- whenever it did arrive in time.
    when (isJust arrived) $ do
        pending <- tls13stPendingRecv <$> getTLS13State ctx
        case pending of
            PendingRecvError err -> do
                modifyTLS13State ctx $ \st -> st{tls13stPendingRecv = NoPendingRecv}
                E.throwIO err
            _ -> return ()

-- | 'waitAuthFailure' with a backend which can give up: no thread, since
-- the receive gives up only before a record begins.  Once begun, only the
-- caller's give-up ends it, and the context cannot be used then.
waitAuthFailureGivingUp :: Context -> STM () -> IO (Maybe a) -> IO (Either a ())
waitAuthFailureGivingUp ctx giveUp given = do
    rtt <- getRTT ctx
    late <- registerDelay rtt
    let between = (readTVar late >>= check) `orElse` giveUp
    r <-
        withReadLockGivingUp ctx giveUp $
            withRxGiveUp ctx (GiveUp between giveUp) $
                E.try $
                    recvData13 ctx
    case r of
        Left () -> return $ Right ()
        Right (Right dat) -> do
            modifyTLS13State ctx $ \st -> st{tls13stPendingRecv = PendingRecvData dat}
            return $ Right ()
        Right (Left e)
            | isJust (E.fromException @GaveUp e) -> return $ Right ()
            | otherwise -> given >>= maybe (E.throwIO e) (return . Left)

rttFactor :: Int
rttFactor = 3

-- | An upper bound of the RTT measured in the handshake, which sets how
-- long to wait for the peer.
maxWaitRTT :: Millisecond
maxWaitRTT = 1000

getRTT :: Context -> IO Int
getRTT ctx = do
    rtt <- tls13stRTT <$> getTLS13State ctx
    let rtt' = max 10 $ fromIntegral $ min maxWaitRTT rtt
    return (rtt' * rttFactor * 1000) -- ms to us

-- | Notify the peer that this side wants to close the connection, by
-- sending close_notify.  It should be called before closing the backend.
-- This doesn't actually close the backend.  Nothing is sent after a failed
-- handshake or a received alert, and a peer which has gone already is not
-- an error.  With 'getBackendSendWith', close_notify is given up on when
-- the peer does not read it for a second or so.
--
-- Proper usage is as follows:
--
-- > ctx <- contextNew <backend> <params>
-- > handshake ctx
-- > ...
-- > bye ctx
--
-- The following code guarantees nothing more, but does no harm.
--
-- > bracket (contextNew <backend> <params>) bye $ \ctx -> do
-- >   handshake ctx
-- >   ...
bye :: MonadIO m => Context -> m ()
bye ctx = byeWith ctx (retry :: STM ())

-- | 'bye' which also gives up once the 'STM' action succeeds, on the
-- peer's last handshake messages and on close_notify alike.  The 'STM'
-- action only bounds the wait; its result is not used, and close_notify
-- is best effort: a peer gone or a send given up on is not reported.
--
-- @since 2.6.4
byeWith :: MonadIO m => Context -> STM a -> m ()
byeWith ctx giveUp0 = liftIO $ do
    let giveUp = void giveUp0
    eof <- ctxEOF ctx
    -- After a failed send, nothing is sent, so nothing is waited for either.
    broken <- ctxTxBroken ctx
    tls13 <- tls13orLater ctx
    when (tls13 && not eof && not broken) $ do
        role <- usingState_ ctx getRole
        if role == ClientRole
            then do
                sending ctx giveUp $ sendCFifNecessary ctx
                -- receiving NewSessionTicket
                let chk = tls13stRecvNST <$> getTLS13State ctx
                recvNST <- chk
                unless recvNST $ do
                    rtt <- getRTT ctx
                    tryRecvHS13 giveUp rtt chk
            else do
                -- receiving Client Finished
                let chk = tls13stRecvCF <$> getTLS13State ctx
                recvCF <- chk
                unless recvCF $ do
                    -- no chance to measure RTT before receiving CF
                    -- fixme: 1sec is good enough?
                    let rtt = 1000000
                    tryRecvHS13 giveUp rtt chk
    bye_ ctx giveUp
  where
    -- Receiving these messages only improves the chances of a later session
    -- resumption, so giving up on them costs nothing important.  We give up in
    -- two different situations, for two different reasons.
    --
    -- First, we need the read lock, because only one thread at a time may read
    -- the connection, but we take it only if it happens to be free.  Another
    -- thread can be sitting in 'recvData' waiting for data that never arrives,
    -- or the receive that 'handshake' starts can still be running, and either
    -- holds the read lock for as long as it lasts.  Waiting for the lock would
    -- therefore hang 'bye', and closing a connection that a reader is stuck on
    -- is exactly what 'bye' is for, so we skip the receive in that case.
    --
    -- Second, if we do get the lock, we wait 'rtt' for the message and then
    -- abandon the receive.  Abandoning it can stop the connection part way
    -- through a record, after which nothing can be read from it again -- which
    -- is acceptable only because we are closing the connection here anyway.
    --
    -- A backend which can give up on a receive does so after 'rtt'; with
    -- one which cannot, the messages are not waited for at all.
    tryRecvHS13 :: STM () -> Int -> IO Bool -> IO ()
    tryRecvHS13 giveUp rtt chk = case ctxBackendRecvWith ctx of
        Nothing -> return ()
        Just _ -> do
            late <- registerDelay rtt
            let g = (readTVar late >>= check) `orElse` giveUp
            void $
                tryWithReadLock ctx $
                    withRxGiveUp ctx (GiveUp g g) $
                        recvHS13 ctx chk `catchException` \e ->
                            -- Only an IOException means that the connection is gone
                            -- (see 'backendRecv'); otherwise close_notify is sent.
                            when (isJust (E.fromException @E.IOException e)) $
                                setEOF ctx

bye_ :: Context -> STM () -> IO ()
bye_ ctx giveUp = do
    -- Although setEOF is always protected by the read lock, here we don't try
    -- to wrap ctxEOF with it, so that function bye can still be called
    -- concurrently to a blocked recvData.
    eof <- ctxEOF ctx
    broken <- ctxTxBroken ctx
    tls13 <- tls13orLater ctx
    -- No response to a post-handshake authentication is waited for.
    (`E.finally` wakePHA ctx) $
        unless (eof || broken) $
            sending ctx giveUp $
                if tls13
                    then sendPacket13 ctx $ Alert13 [(AlertLevel_Warning, CloseNotify)]
                    else sendPacket12 ctx $ Alert [(AlertLevel_Warning, CloseNotify)]

-- | A send of 'bye', with the write lock: given up on, as is the wait for
-- the lock, after a second or after 'rtt' if longer, or with the 'STM'
-- action.  With a backend which cannot give up on a send, it may block.
-- The peer may have closed the connection without close_notify: EPIPE or
-- ECONNRESET is then just the end of it.
sending :: Context -> STM () -> IO () -> IO ()
sending ctx giveUp send = E.handleJust ignorable return $ do
    rtt <- getRTT ctx
    late <- registerDelay $ max 1000000 rtt
    let g = (readTVar late >>= check) `orElse` giveUp
    void $ withWriteLockGivingUp ctx g $ withTxGiveUp ctx g send
  where
    ignorable :: E.SomeException -> Maybe ()
    ignorable e
        | Just ioe <- E.fromException e, ioe_type ioe == ResourceVanished = Just ()
        | Just e' <- E.fromException e, e' == gaveUpSending = Just ()
        | otherwise = Nothing

-- | If the ALPN extension has been used, this will
-- return the protocol agreed upon.
getNegotiatedProtocol :: MonadIO m => Context -> m (Maybe ByteString)
getNegotiatedProtocol ctx = liftIO $ usingState_ ctx S.getNegotiatedProtocol

-- | If the Server Name Indication extension has been used, return the
-- hostname specified by the client.
getClientSNI :: MonadIO m => Context -> m (Maybe HostName)
getClientSNI ctx = liftIO $ usingState_ ctx S.getClientSNI

sendCFifNecessary :: Context -> IO ()
sendCFifNecessary ctx = do
    st <- getTLS13State ctx
    let recvSF = tls13stRecvSF st
        sentCF = tls13stSentCF st
    when (recvSF && not sentCF) $ do
        msend <- readIORef (ctxPendingSendAction ctx)
        case msend of
            Nothing -> return ()
            Just sendAction -> do
                sendAction ctx
                writeIORef (ctxPendingSendAction ctx) Nothing

-- | Sending a bunch of data.
-- It will automatically chunk data to acceptable record sizes.
sendData :: MonadIO m => Context -> L.ByteString -> m ()
sendData _ "" = return ()
sendData ctx dataToSend = liftIO $ do
    tls13 <- tls13orLater ctx
    when tls13 $ withWriteLock ctx $ sendCFifNecessary ctx
    withWriteLock ctx $ sendDataLocked ctx tls13 dataToSend

-- | 'sendData' which gives up once the 'STM' action succeeds, also while
-- waiting for the write lock.  Given up on before anything is sent, the
-- context can still be used.  Given up on after that, part of the data
-- may have been sent, and how much is not known, so later sends throw.
-- With a backend which cannot give up on a send, only the wait for the
-- lock is given up on.
--
-- @since 2.6.4
sendDataWith :: MonadIO m => Context -> L.ByteString -> STM a -> m (Either a ())
sendDataWith _ "" _ = return $ Right ()
sendDataWith ctx dataToSend giveUp = liftIO $ do
    early <- atomically $ (Just <$> giveUp) `orElse` return Nothing
    case early of
        Just a -> return $ Left a
        Nothing -> do
            tls13 <- tls13orLater ctx
            (giveUp', given) <- recording giveUp
            withWriteLockGivingUp ctx giveUp (withTxGiveUp ctx giveUp' (send tls13))
                `E.catch` \e ->
                    if e == gaveUpSending
                        then given >>= maybe (E.throwIO e) (return . Left)
                        else E.throwIO e
  where
    send tls13 = do
        when tls13 $ sendCFifNecessary ctx
        sendDataLocked ctx tls13 dataToSend

sendDataLocked :: Context -> Bool -> L.ByteString -> IO ()
sendDataLocked ctx tls13 dataToSend = do
    checkValid ctx
    -- All chunks are protected with the same write lock because we don't
    -- want to interleave writes from other threads in the middle of our
    -- possibly large write.
    mlen <- getPeerRecordLimit ctx -- plaintext, don't adjust for TLS 1.3
    mapM_ (mapChunks_ mlen sendP) (L.toChunks dataToSend)
  where
    sendP bs
        | tls13 = do
            updateKeyBeforeLimit ctx
            sendPacket13 ctx $ AppData13 bs
            -- a KeyUpdate requested from now on is answered again
            modifyTLS13State ctx $ \st -> st{tls13stKeyUpdateResponded = False}
            role <- usingState_ ctx getRole
            sentCF <- tls13stSentCF <$> getTLS13State ctx
            rtt0 <- tls13st0RTT <$> getTLS13State ctx
            when (role == ClientRole && rtt0 && not sentCF) $
                modifyTLS13State ctx $
                    \st -> st{tls13stPendingSentData = tls13stPendingSentData st . (bs :)}
        | otherwise = sendPacket12 ctx $ AppData bs

-- RFC 9846 Section 5.5: the keys are updated before the records sent
-- under them reach the limit.  Early data cannot do so and stops there.
updateKeyBeforeLimit :: Context -> IO ()
updateKeyBeforeLimit ctx = do
    (mcipher, level, sqn) <- getTxSequence ctx
    case mcipher of
        Just cipher | sqn >= recordLimit cipher -> do
            updated <-
                if level == CryptApplicationSecret
                    then sendKeyUpdate ctx UpdateNotRequested
                    else return False
            unless updated $
                E.throwIO $
                    PostHandshake $
                        Error_Misc "the key usage limit is reached"
        _ -> return ()
  where
    -- AES-GCM allows 2^24.5 full-size records.  The sequence number of
    -- ChaCha20-Poly1305 would wrap before its limit.
    recordLimit cipher = fromMaybe forCipher $ limitRecordsPerKey $ sharedLimit $ ctxShared ctx
      where
        forCipher
            | bulkName (cipherBulk cipher) == "CHACHA20POLY1305" = 2 ^ (62 :: Int)
            | otherwise = 2 ^ (24 :: Int)

-- | Get data out of Data packet, and automatically renegotiate if a Handshake
-- ClientHello is received.  An empty result means EOF, after which it
-- throws 'PostHandshake' 'Error_EOF'.  Use 'closeNotifyReceived' to tell
-- an orderly closure from a truncation.
--
-- An exception from the backend's receive passes through.  See
-- 'Network.TLS.backendRecv' for when it may be called again.
recvData :: MonadIO m => Context -> m ByteString
recvData ctx = liftIO $ do
    tls13 <- tls13orLater ctx
    withReadLock ctx $ do
        checkValid ctx
        -- We protect with a read lock both reception and processing of the
        -- packet, because don't want another thread to receive a new packet
        -- before this one has been fully processed.
        --
        -- Even when recvData12/recvData13 loops, we only need to call function
        -- checkValid once.  Since we hold the read lock, no concurrent call
        -- will impact the validity of the context.
        if tls13 then recvData13 ctx else recvData12 ctx

-- | 'recvData' which gives up once the 'STM' action succeeds, also while
-- waiting for the read lock.  It gives up only between records, and the
-- context can still be used then.  A record which has begun is read to
-- its end unless the 'STM' action succeeds meanwhile: then it throws, and
-- so do later receives.  With a backend which cannot give up on a
-- receive, only the wait for the lock is given up on.
--
-- A send which the receive makes, such as a response to KeyUpdate or an
-- alert, gives up too, also while waiting for the write lock.  It then
-- throws, and the context can only be closed.
--
-- @since 2.6.4
recvDataWith :: MonadIO m => Context -> STM a -> m (Either a ByteString)
recvDataWith ctx giveUp = liftIO $ do
    tls13 <- tls13orLater ctx
    (giveUp', given) <- recording giveUp
    fmap join $ withReadLockGivingUp ctx giveUp $ do
        checkValid ctx
        withRxGiveUp ctx (GiveUp giveUp' giveUp') $
            (Right <$> if tls13 then recvData13 ctx else recvData12 ctx)
                `E.catch` \GaveUp -> given >>= maybe (E.throwIO GaveUp) (return . Left)

recvData12 :: Context -> IO ByteString
recvData12 ctx = do
    pending <- atomicModifyIORef' (ctxPendingAppData ctx) $ \xs -> ([], reverse xs)
    if null pending
        then recvPacket12 ctx >>= either (onError terminate12) process
        else return $ B.concat pending
  where
    process (Handshake [ch@ClientHello{}] [b]) =
        renegotiate ctx (ch, b) >> recvData12 ctx
    process (Handshake [hr@HelloRequest] [b]) =
        renegotiate ctx (hr, b) >> recvData12 ctx
    -- UserCanceled should be followed by a close_notify.
    -- fixme: is it safe to call recvData12?
    process (Alert [(AlertLevel_Warning, UserCanceled)]) = return B.empty
    process (Alert [(AlertLevel_Warning, CloseNotify)]) = setCloseNotify ctx >> tryBye ctx >> return B.empty
    process (Alert [(AlertLevel_Fatal, desc)]) = do
        setEOF ctx
        E.throwIO
            ( Terminated
                True
                ("received fatal error: " ++ show desc)
                (Error_Protocol "remote side fatal error" desc)
            )

    -- when receiving empty appdata, we just retry to get some data.
    process (AppData "") = recvData12 ctx
    process (AppData x) = return x
    process p = do
        let reason = "unexpected message " ++ show p
        terminate12 (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason

    terminate12 = terminateWithWriteLock ctx (sendPacket12 ctx . Alert)

recvData13 :: Context -> IO ByteString
recvData13 ctx = do
    pending <- tls13stPendingRecv <$> getTLS13State ctx
    case pending of
        NoPendingRecv -> do
            pkt <- recvPacket13 ctx
            either (onError (terminate13 ctx)) process pkt
        PendingRecvData dat -> do
            clearPending
            return dat
        PendingRecvError err -> do
            clearPending
            E.throwIO err
  where
    clearPending = modifyTLS13State ctx $ \st -> st{tls13stPendingRecv = NoPendingRecv}

    -- RFC 9846 Section 4.7.2: the client's Certificate, CertificateVerify
    -- and Finished appear consecutively.  The waiters get this error.
    checkPHAResponse = do
        responding <- tls13stPHAResponding <$> getTLS13State ctx
        when responding $ do
            let reason = "message inside a post-handshake authentication response"
                err = Error_Protocol reason UnexpectedMessage
            modifyTLS13State ctx $ \st -> st{tls13stPHA = fmap (\(mv, _) -> (mv, err)) (tls13stPHA st)}
            terminate13 ctx err AlertLevel_Fatal UnexpectedMessage reason

    -- RFC 9846 Section 6: the level is ignored.  Alerts other than the
    -- closure ones are error alerts, even at the warning level.
    -- UserCanceled MUST be followed by a CloseNotify.
    process (Alert13 [(_, UserCanceled)]) = return B.empty
    process (Alert13 [(_, CloseNotify)]) = setCloseNotify ctx >> tryBye ctx >> return B.empty
    process (Alert13 [(_, desc)]) = do
        setEOF ctx
        E.throwIO
            ( Terminated
                True
                ("received fatal error: " ++ show desc)
                (Error_Protocol "remote side fatal error" desc)
            )
    process (Handshake13 hs bs) = do
        loopHandshake13 $ zip hs bs
        recvData13 ctx
    -- when receiving empty appdata, we just retry to get some data.
    process (AppData13 "") = checkPHAResponse >> recvData13 ctx
    process (AppData13 x) = do
        checkPHAResponse
        let chunkLen = fromIntegral $ C8.length x
        established <- ctxEstablished ctx
        case established of
            EarlyDataAllowed maxSize
                | chunkLen <= maxSize -> do
                    setEstablished ctx $ EarlyDataAllowed (maxSize - chunkLen)
                    return x
                | otherwise ->
                    let reason = "early data overflow"
                     in terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
            Established -> resetTLS13KeyUpdateCount ctx >> return x
            _ -> throwCore $ Error_Protocol "data at not-established" UnexpectedMessage
    process ChangeCipherSpec13 = do
        established <- ctxEstablished ctx
        if established /= Established
            then recvData13 ctx
            else do
                let reason = "CSS after Finished"
                terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
    process p = do
        let reason = "unexpected message " ++ show p
        terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason

    loopHandshake13 [] = return ()
    -- fixme: some implementations send multiple NST at the same time.
    -- Only the first one is used at this moment.
    loopHandshake13 ((NewSessionTicket13 life add nonce (SessionIDorTicket_ ticket) exts, _b) : hbs) = do
        role <- usingState_ ctx S.getRole
        unless (role == ClientRole) $ do
            let reason = "Session ticket is allowed for client only"
            terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
        -- This part is similar to handshake code, so protected with
        -- read+write locks (which is also what we use for all calls to the
        -- session manager).
        withWriteLock ctx $ do
            Just resumptionSecret <- usingHState ctx getTLS13ResumptionSecret
            (_, usedCipher, _, _) <- getTxRecordState ctx
            -- mMaxSize is always Just, but anyway
            let extract (EarlyDataIndication mMaxSize) =
                    fromMaybe 0 mMaxSize
            let choice = makeCipherChoice TLS13 usedCipher
                psk = derivePSK choice resumptionSecret nonce
                maxSize =
                    lookupAndDecode
                        EID_EarlyData
                        MsgTNewSessionTicket
                        exts
                        0
                        extract
                life7d = min life 604800 -- 7 days max
            tinfo <- createTLS13TicketInfo life7d (Right add) Nothing
            sdata <- getSessionData13 ctx usedCipher tinfo maxSize psk
            let ticket' = B.copy ticket
            void $ sessionEstablish (sharedSessionManager $ ctxShared ctx) ticket' sdata
            modifyTLS13State ctx $ \st -> st{tls13stRecvNST = True}
        loopHandshake13 hbs
    loopHandshake13 ((KeyUpdate13 mode, _b) : hbs) = do
        checkPHAResponse
        when (ctxQUICMode ctx) $ do
            let reason = "KeyUpdate is not allowed for QUIC"
            terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
        aligned <- isAligned ctx hbs
        unless aligned $
            terminate13
                ctx
                (Error_Misc notAligned)
                AlertLevel_Fatal
                UnexpectedMessage
                notAligned
        established <- ctxEstablished ctx
        -- Though RFC 8446 Sec 4.6.3 does not clearly says,
        -- unidirectional key update is legal.
        -- So, we don't have to check if this key update is corresponding
        -- to key update (update_requested) which we sent.
        if established == Established
            then do
                case limitKeyUpdate $ sharedLimit $ ctxShared ctx of
                    Just limit | limit > 0 -> do
                        count <- incrementTLS13KeyUpdateCount ctx
                        when (count > limit) $ do
                            let reason = "too many consecutive KeyUpdate messages"
                            terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
                    _ -> return ()
                keyUpdate ctx getRxRecordState setRxRecordState
                -- Write lock wraps both actions because we don't want another
                -- packet to be sent by another thread before the Tx state is
                -- updated.
                when (mode == UpdateRequested) $
                    withWriteLock ctx $
                        respondToKeyUpdate ctx
                loopHandshake13 hbs
            else do
                let reason = "received key update before established"
                terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
    -- Client only.  Before Established, it belongs to the handshake that
    -- 0-RTT left to the pending actions.
    loopHandshake13 (hb@(CertRequest13{}, _) : hbs) = do
        established <- ctxEstablished ctx
        if established == Established
            then postHandshakeAuthWith ctx hb >> loopHandshake13 hbs
            else loopPending hb hbs
    loopHandshake13 (hb : hbs) = loopPending hb hbs

    loopPending hb@(h, _) hbs = do
        rtt0 <- tls13st0RTT <$> getTLS13State ctx
        when rtt0 $ case h of
            ServerHello13 SH{..} ->
                when (isHelloRetryRequest shRandom) $ do
                    clearTxRecordState ctx
                    let reason = "HRR is not allowed for 0-RTT"
                    terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
            _ -> return ()
        popAction ctx hb hbs
        loopHandshake13 hbs

recvHS13 :: Context -> IO Bool -> IO ()
recvHS13 ctx breakLoop = do
    pkt <- recvPacket13 ctx
    -- fixme: Left
    either (\_ -> return ()) process pkt
  where
    -- UserCanceled MUST be followed by a CloseNotify.
    process (Alert13 [(_, UserCanceled)]) = recvHS13 ctx breakLoop
    process (Alert13 [(_, CloseNotify)]) = setCloseNotify ctx >> tryBye ctx
    process (Alert13 [(_, _desc)]) = setEOF ctx
    process (Handshake13 hs bs) = do
        loopHandshake13 $ zip hs bs
        stop <- breakLoop
        unless stop $ recvHS13 ctx breakLoop
    process _ = recvHS13 ctx breakLoop

    loopHandshake13 [] = return ()
    -- fixme: some implementations send multiple NST at the same time.
    -- Only the first one is used at this moment.
    loopHandshake13 ((NewSessionTicket13 life add nonce (SessionIDorTicket_ ticket) exts, _b) : hbs) = do
        role <- usingState_ ctx S.getRole
        unless (role == ClientRole) $ do
            let reason = "Session ticket is allowed for client only"
            terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
        -- This part is similar to handshake code, so protected with
        -- read+write locks (which is also what we use for all calls to the
        -- session manager).
        withWriteLock ctx $ do
            Just resumptionSecret <- usingHState ctx getTLS13ResumptionSecret
            (_, usedCipher, _, _) <- getTxRecordState ctx
            let choice = makeCipherChoice TLS13 usedCipher
                psk = derivePSK choice resumptionSecret nonce
                maxSize =
                    lookupAndDecode
                        EID_EarlyData
                        MsgTNewSessionTicket
                        exts
                        0
                        (\(EarlyDataIndication mms) -> fromJust mms)
                life7d = min life 604800 -- 7 days max
            tinfo <- createTLS13TicketInfo life7d (Right add) Nothing
            sdata <- getSessionData13 ctx usedCipher tinfo maxSize psk
            let ticket' = B.copy ticket
            void $ sessionEstablish (sharedSessionManager $ ctxShared ctx) ticket' sdata
            modifyTLS13State ctx $ \st -> st{tls13stRecvNST = True}
        loopHandshake13 hbs
    loopHandshake13 (hb : hbs) = do
        popAction ctx hb hbs
        loopHandshake13 hbs

terminate13
    :: Context -> TLSError -> AlertLevel -> AlertDescription -> String -> IO a
terminate13 ctx = terminateWithWriteLock ctx (sendPacket13 ctx . Alert13)

popAction :: Context -> Handshake13R -> [Handshake13R] -> IO ()
popAction ctx hb@(h, _b) hbs = do
    mPendingRecvAction <- popPendingRecvAction ctx
    case mPendingRecvAction of
        -- RFC 9846 Section 6.2: a message no pending action expects is
        -- unexpected_message, not dropped.
        Nothing -> do
            let reason = "unexpected handshake message " ++ show h
            terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
        Just action -> do
            -- Pending actions are executed with read+write locks, just
            -- like regular handshake code.  A failure has sent an alert,
            -- so the connection is closed.
            (`E.onException` setEOF ctx) $
                withWriteLock ctx $
                    handleException ctx $ do
                        case action of
                            PendingRecvAction needAligned pa -> do
                                checkAligned needAligned
                                updateTranscriptHash13 ctx hb
                                pa h
                            PendingRecvActionSelfUpdate needAligned pa -> do
                                checkAligned needAligned
                                pa hb
                            PendingRecvActionHash needAligned pa -> do
                                checkAligned needAligned
                                d <- transcriptHash ctx "Pending action"
                                updateTranscriptHash13 ctx hb
                                pa d h
                        -- Client: after receiving SH, app data is coming.
                        -- this loop tries to receive it.
                        -- App key must be installed before receiving
                        -- the app data.
                        sendCFifNecessary ctx
  where
    -- The write lock is held here, so 'handleException' sends the alert.
    checkAligned needAligned = when needAligned $ do
        aligned <- isAligned ctx hbs
        unless aligned $ throwCore $ Error_Protocol notAligned UnexpectedMessage

-- RFC 9846 Section 5.1: a message before a key change must end its
-- record, so neither a message nor a fragment may follow it.
isAligned :: Context -> [Handshake13R] -> IO Bool
isAligned ctx hbs = do
    complete <- isRecvComplete ctx
    return $ complete && null hbs

notAligned :: String
notAligned = "received message not aligned with record boundary"

-- the other side could have close the connection already, so wrap
-- this in a try and ignore all exceptions
tryBye :: Context -> IO ()
tryBye ctx = catchException (bye_ ctx retry) (\_ -> return ()) `E.finally` setEOF ctx

onError
    :: Monad m
    => (TLSError -> AlertLevel -> AlertDescription -> String -> m ByteString)
    -> TLSError
    -> m ByteString
onError _ Error_EOF =
    -- Not really an error.
    return B.empty
onError terminate err = terminate err lvl ad reason
  where
    (lvl, ad) = errorToAlert err
    reason = errorToAlertMessage err

terminateWithWriteLock
    :: Context
    -> ([(AlertLevel, AlertDescription)] -> IO ())
    -> TLSError
    -> AlertLevel
    -> AlertDescription
    -> String
    -> IO a
terminateWithWriteLock ctx send err level desc reason = withWriteLock ctx $ do
    tls13 <- tls13orLater ctx
    unless tls13 $ do
        -- TLS 1.2 uses the same session ID and session data
        -- for all resumed sessions.
        --
        -- TLS 1.3 changes session data for every resumed session.
        session <- usingState_ ctx getSession
        case session of
            Session Nothing -> return ()
            Session (Just sid) ->
                -- calling even session ticket manager anyway
                sessionInvalidate (sharedSessionManager $ ctxShared ctx) sid
    catchException (send [(level, desc)]) (\_ -> return ())
    setEOF ctx
    debugError (ctxDebug ctx) reason
    E.throwIO (Terminated False reason err)

-- | Whether the peer has sent close_notify.  If 'recvData' returns an
-- empty result and this is 'False', the transport was closed without
-- close_notify, so the data received may be truncated.
--
-- @since 2.5.0
closeNotifyReceived :: MonadIO m => Context -> m Bool
closeNotifyReceived = liftIO . ctxCloseNotify

{-# DEPRECATED recvData' "use recvData that returns strict bytestring" #-}

-- | Same as 'recvData' but returns a lazy bytestring.
recvData' :: MonadIO m => Context -> m L.ByteString
recvData' ctx = L.fromChunks . (: []) <$> recvData ctx
