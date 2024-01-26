{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_HADDOCK hide #-}

module Network.TLS.Core (
    -- * Internal packet sending and receiving
    sendPacket,
    recvPacket,

    -- * Initialisation and Termination of context
    bye,
    handshake,

    -- * Application Layer Protocol Negotiation
    getNegotiatedProtocol,

    -- * Server Name Indication
    getClientSNI,

    -- * High level API
    sendData,
    recvData,
    recvData',
    updateKey,
    KeyUpdateRequest (..),
    requestCertificate,
) where

import qualified Control.Exception as E
import Control.Monad (unless, void, when)
import Control.Monad.State.Strict
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as L
import Data.IORef
import System.Timeout

import Network.TLS.Cipher
import Network.TLS.Context
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.IO
import Network.TLS.KeySchedule
import Network.TLS.Parameters
import Network.TLS.PostHandshake
import Network.TLS.Session
import Network.TLS.State (getRole, getSession)
import qualified Network.TLS.State as S
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types (
    AnyTrafficSecret (..),
    ApplicationSecret,
    HostName,
    Role (..),
 )
import Network.TLS.Util (catchException, mapChunks_)

-- | Handshake for a new TLS connection
-- This is to be called at the beginning of a connection, and during renegotiation
handshake :: MonadIO m => Context -> m ()
handshake ctx = do
    handshake_ ctx
    -- Trying to receive an alert of client authentication failure
    liftIO $ do
        tls13 <- tls13orLater ctx
        sentClientCert <- tls13stSentClientCert <$> getTLS13State ctx
        when (tls13 && sentClientCert) $ do
            rtt <- getRTT ctx
            mdat <- timeout rtt $ recvData ctx
            case mdat of
                Nothing -> return ()
                Just dat -> modifyTLS13State ctx $ \st -> st{tls13stPendingRecvData = Just dat}

rttFactor :: Int
rttFactor = 2

getRTT :: Context -> IO Int
getRTT ctx = do
    rtt <- tls13stRTT <$> getTLS13State ctx
    return (rtt * rttFactor)

-- | notify the context that this side wants to close connection.
-- this is important that it is called before closing the handle, otherwise
-- the session might not be resumable (for version < TLS1.2).
--
-- this doesn't actually close the handle
bye :: MonadIO m => Context -> m ()
bye ctx = liftIO $ do
    eof <- ctxEOF ctx
    tls13 <- tls13orLater ctx
    when (tls13 && not eof) $ do
        role <- usingState_ ctx getRole
        if role == ClientRole
            then do
                sendCFifNecessary ctx
                -- receiving NewSessionTicket
                recvNST <- tls13stRecvNST <$> getTLS13State ctx
                unless recvNST $ do
                    rtt <- getRTT ctx
                    void $ timeout rtt $ recvData ctx
            else do
                -- receiving Client Finished
                recvCF <- tls13stRecvCF <$> getTLS13State ctx
                unless recvCF $
                    void $
                        timeout 500000 (recvData ctx)
    bye_ ctx

bye_ :: MonadIO m => Context -> m ()
bye_ ctx = liftIO $ do
    -- Although setEOF is always protected by the read lock, here we don't try
    -- to wrap ctxEOF with it, so that function bye can still be called
    -- concurrently to a blocked recvData.
    eof <- ctxEOF ctx
    tls13 <- tls13orLater ctx
    unless eof $
        withWriteLock ctx $
            if tls13
                then sendPacket13 ctx $ Alert13 [(AlertLevel_Warning, CloseNotify)]
                else sendPacket ctx $ Alert [(AlertLevel_Warning, CloseNotify)]

-- | If the ALPN extensions have been used, this will
-- return get the protocol agreed upon.
getNegotiatedProtocol :: MonadIO m => Context -> m (Maybe B.ByteString)
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

-- | sendData sends a bunch of data.
-- It will automatically chunk data to acceptable packet size
sendData :: MonadIO m => Context -> L.ByteString -> m ()
sendData _ "" = return ()
sendData ctx dataToSend = liftIO $ do
    tls13 <- tls13orLater ctx
    sentCF <- tls13stSentCF <$> getTLS13State ctx
    let sendP bs
            | tls13 = do
                sendPacket13 ctx $ AppData13 bs
                when (not sentCF) $
                    modifyTLS13State ctx $
                        \st -> st{tls13stPendingSentData = tls13stPendingSentData st . (bs :)}
            | otherwise = sendPacket ctx $ AppData bs
    when tls13 $ sendCFifNecessary ctx
    withWriteLock ctx $ do
        checkValid ctx
        -- All chunks are protected with the same write lock because we don't
        -- want to interleave writes from other threads in the middle of our
        -- possibly large write.
        let len = ctxFragmentSize ctx
        mapM_ (mapChunks_ len sendP) (L.toChunks dataToSend)

-- | Get data out of Data packet, and automatically renegotiate if a Handshake
-- ClientHello is received.  An empty result means EOF.
recvData :: MonadIO m => Context -> m B.ByteString
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

recvData12 :: Context -> IO B.ByteString
recvData12 ctx = do
    pkt <- recvPacket ctx
    either (onError terminate) process pkt
  where
    process (Handshake [ch@ClientHello{}]) =
        handshakeWith ctx ch >> recvData12 ctx
    process (Handshake [hr@HelloRequest]) =
        handshakeWith ctx hr >> recvData12 ctx
    process (Alert [(AlertLevel_Warning, CloseNotify)]) = tryBye ctx >> setEOF ctx >> return B.empty
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
    process p =
        let reason = "unexpected message " ++ show p
         in terminate (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason

    terminate = terminateWithWriteLock ctx (sendPacket ctx . Alert)

recvData13 :: Context -> IO B.ByteString
recvData13 ctx = do
    mdat <- tls13stPendingRecvData <$> getTLS13State ctx
    case mdat of
        Nothing -> do
            pkt <- recvPacket13 ctx
            either (onError terminate) process pkt
        Just dat -> do
            modifyTLS13State ctx $ \st -> st{tls13stPendingRecvData = Nothing}
            return dat
  where
    process (Alert13 [(AlertLevel_Warning, UserCanceled)]) = return B.empty
    process (Alert13 [(AlertLevel_Warning, CloseNotify)]) = tryBye ctx >> setEOF ctx >> return B.empty
    process (Alert13 [(AlertLevel_Fatal, desc)]) = do
        setEOF ctx
        E.throwIO
            ( Terminated
                True
                ("received fatal error: " ++ show desc)
                (Error_Protocol "remote side fatal error" desc)
            )
    process (Handshake13 hs) = do
        loopHandshake13 hs
        recvData13 ctx
    -- when receiving empty appdata, we just retry to get some data.
    process (AppData13 "") = recvData13 ctx
    process (AppData13 x) = do
        let chunkLen = C8.length x
        established <- ctxEstablished ctx
        case established of
            EarlyDataAllowed maxSize
                | chunkLen <= maxSize -> do
                    setEstablished ctx $ EarlyDataAllowed (maxSize - chunkLen)
                    return x
                | otherwise ->
                    let reason = "early data overflow"
                     in terminate (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
            EarlyDataNotAllowed n
                | n > 0 -> do
                    setEstablished ctx $ EarlyDataNotAllowed (n - 1)
                    recvData13 ctx -- ignore "x"
                | otherwise ->
                    let reason = "early data deprotect overflow"
                     in terminate (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
            Established -> return x
            NotEstablished -> throwCore $ Error_Protocol "data at not-established" UnexpectedMessage
    process ChangeCipherSpec13 = do
        established <- ctxEstablished ctx
        if established /= Established
            then recvData13 ctx
            else do
                let reason = "CSS after Finished"
                terminate (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
    process p =
        let reason = "unexpected message " ++ show p
         in terminate (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason

    loopHandshake13 [] = return ()
    -- fixme: some implementations send multiple NST at the same time.
    -- Only the first one is used at this moment.
    loopHandshake13 (NewSessionTicket13 life add nonce label exts : hs) = do
        modifyTLS13State ctx $ \st -> st{tls13stRecvCF = True}
        role <- usingState_ ctx S.getRole
        unless (role == ClientRole) $
            let reason = "Session ticket is allowed for client only"
             in terminate (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
        -- This part is similar to handshake code, so protected with
        -- read+write locks (which is also what we use for all calls to the
        -- session manager).
        withWriteLock ctx $ do
            Just resumptionMasterSecret <- usingHState ctx getTLS13ResumptionSecret
            (_, usedCipher, _, _) <- getTxState ctx
            let choice = makeCipherChoice TLS13 usedCipher
                psk = derivePSK choice resumptionMasterSecret nonce
                maxSize = case extensionLookup EID_EarlyData exts
                    >>= extensionDecode MsgTNewSessionTicket of
                    Just (EarlyDataIndication (Just ms)) -> fromIntegral $ safeNonNegative32 ms
                    _ -> 0
                life7d = min life 604800 -- 7 days max
            tinfo <- createTLS13TicketInfo life7d (Right add) Nothing
            sdata <- getSessionData13 ctx usedCipher tinfo maxSize psk
            let label' = B.copy label
            void $ sessionEstablish (sharedSessionManager $ ctxShared ctx) label' sdata
            modifyTLS13State ctx $ \st -> st{tls13stRecvNST = True}
        -- putStrLn $ "NewSessionTicket received: lifetime = " ++ show life ++ " sec"
        loopHandshake13 hs
    loopHandshake13 (KeyUpdate13 mode : hs) = do
        when (ctxQUICMode ctx) $ do
            let reason = "KeyUpdate is not allowed for QUIC"
            terminate (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
        checkAlignment hs
        established <- ctxEstablished ctx
        -- Though RFC 8446 Sec 4.6.3 does not clearly says,
        -- unidirectional key update is legal.
        -- So, we don't have to check if this key update is corresponding
        -- to key update (update_requested) which we sent.
        if established == Established
            then do
                keyUpdate ctx getRxState setRxState
                -- Write lock wraps both actions because we don't want another
                -- packet to be sent by another thread before the Tx state is
                -- updated.
                when (mode == UpdateRequested) $ withWriteLock ctx $ do
                    sendPacket13 ctx $ Handshake13 [KeyUpdate13 UpdateNotRequested]
                    keyUpdate ctx getTxState setTxState
                loopHandshake13 hs
            else do
                let reason = "received key update before established"
                terminate (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
    loopHandshake13 (h@CertRequest13{} : hs) =
        postHandshakeAuthWith ctx h >> loopHandshake13 hs
    loopHandshake13 (h@Certificate13{} : hs) =
        postHandshakeAuthWith ctx h >> loopHandshake13 hs
    loopHandshake13 (h : hs) = do
        mPendingRecvAction <- popPendingRecvAction ctx
        case mPendingRecvAction of
            Nothing ->
                let reason = "unexpected handshake message " ++ show h
                 in terminate (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
            Just action -> do
                -- Pending actions are executed with read+write locks, just
                -- like regular handshake code.
                withWriteLock ctx $
                    handleException ctx $ do
                        case action of
                            PendingRecvAction needAligned pa -> do
                                when needAligned $ checkAlignment hs
                                processHandshake13 ctx h
                                pa h
                            PendingRecvActionHash needAligned pa -> do
                                when needAligned $ checkAlignment hs
                                d <- transcriptHash ctx
                                processHandshake13 ctx h
                                pa d h
                        -- Client: after receiving SH, app data is coming.
                        -- this loop tries to receive it.
                        -- App key must be installed before receiving
                        -- the app data.
                        sendCFifNecessary ctx
                loopHandshake13 hs

    terminate = terminateWithWriteLock ctx (sendPacket13 ctx . Alert13)

    checkAlignment hs = do
        complete <- isRecvComplete ctx
        unless (complete && null hs) $
            let reason = "received message not aligned with record boundary"
             in terminate (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason

-- the other side could have close the connection already, so wrap
-- this in a try and ignore all exceptions
tryBye :: Context -> IO ()
tryBye ctx = catchException (bye_ ctx) (\_ -> return ())

onError
    :: Monad m
    => (TLSError -> AlertLevel -> AlertDescription -> String -> m B.ByteString)
    -> TLSError
    -> m B.ByteString
onError _ Error_EOF =
    -- Not really an error.
    return B.empty
onError terminate err =
    let (lvl, ad) = errorToAlert err
     in terminate err lvl ad (errorToAlertMessage err)

terminateWithWriteLock
    :: Context
    -> ([(AlertLevel, AlertDescription)] -> IO ())
    -> TLSError
    -> AlertLevel
    -> AlertDescription
    -> String
    -> IO a
terminateWithWriteLock ctx send err level desc reason = do
    session <- usingState_ ctx getSession
    -- Session manager is always invoked with read+write locks, so we merge this
    -- with the alert packet being emitted.
    withWriteLock ctx $ do
        case session of
            Session Nothing -> return ()
            Session (Just sid) -> sessionInvalidate (sharedSessionManager $ ctxShared ctx) sid
        catchException (send [(level, desc)]) (\_ -> return ())
    setEOF ctx
    E.throwIO (Terminated False reason err)

{-# DEPRECATED recvData' "use recvData that returns strict bytestring" #-}

-- | same as recvData but returns a lazy bytestring.
recvData' :: MonadIO m => Context -> m L.ByteString
recvData' ctx = L.fromChunks . (: []) <$> recvData ctx

keyUpdate
    :: Context
    -> (Context -> IO (Hash, Cipher, CryptLevel, C8.ByteString))
    -> (Context -> Hash -> Cipher -> AnyTrafficSecret ApplicationSecret -> IO ())
    -> IO ()
keyUpdate ctx getState setState = do
    (usedHash, usedCipher, level, applicationSecretN) <- getState ctx
    unless (level == CryptApplicationSecret) $
        throwCore $
            Error_Protocol
                "tried key update without application traffic secret"
                InternalError
    let applicationSecretN1 =
            hkdfExpandLabel usedHash applicationSecretN "traffic upd" "" $
                hashDigestSize usedHash
    setState ctx usedHash usedCipher (AnyTrafficSecret applicationSecretN1)

-- | How to update keys in TLS 1.3
data KeyUpdateRequest
    = -- | Unidirectional key update
      OneWay
    | -- | Bidirectional key update (normal case)
      TwoWay
    deriving (Eq, Show)

-- | Updating appication traffic secrets for TLS 1.3.
--   If this API is called for TLS 1.3, 'True' is returned.
--   Otherwise, 'False' is returned.
updateKey :: MonadIO m => Context -> KeyUpdateRequest -> m Bool
updateKey ctx way = liftIO $ do
    tls13 <- tls13orLater ctx
    when tls13 $ do
        let req = case way of
                OneWay -> UpdateNotRequested
                TwoWay -> UpdateRequested
        -- Write lock wraps both actions because we don't want another packet to
        -- be sent by another thread before the Tx state is updated.
        withWriteLock ctx $ do
            sendPacket13 ctx $ Handshake13 [KeyUpdate13 req]
            keyUpdate ctx getTxState setTxState
    return tls13
