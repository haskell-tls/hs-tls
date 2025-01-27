{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.Common (
    handshakeFailed,
    handleException,
    unexpected,
    newSession,
    handshakeDone12,
    ensureNullCompression,
    ticketOrSessionID12,

    -- * sending packets
    sendCCSandFinished,

    -- * receiving packets
    RecvState (..),
    runRecvState,
    runRecvStateHS,
    recvPacketHandshake,
    onRecvStateHandshake,
    ensureRecvComplete,
    processExtendedMainSecret,
    getSessionData,
    storePrivInfo,
    isSupportedGroup,
    checkSupportedGroup,
    errorToAlert,
    errorToAlertMessage,
    expectFinished,
    processCertificate,
    --
    setPeerRecordSizeLimit,
) where

import Control.Concurrent.MVar
import Control.Exception (IOException, fromException, handle, throwIO)
import Control.Monad.State.Strict
import qualified Data.ByteString as B

import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.Measurement
import Network.TLS.Parameters
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types
import Network.TLS.Util
import Network.TLS.X509

handshakeFailed :: TLSError -> IO ()
handshakeFailed err = throwIO $ HandshakeFailed err

handleException :: Context -> IO () -> IO ()
handleException ctx f = catchException f $ \exception -> do
    -- If the error was an Uncontextualized TLSException, we replace the
    -- context with HandshakeFailed. If it's anything else, we convert
    -- it to a string and wrap it with Error_Misc and HandshakeFailed.
    let tlserror = case fromException exception of
            Just e | Uncontextualized e' <- e -> e'
            _ -> Error_Misc (show exception)
    established <- ctxEstablished ctx
    setEstablished ctx NotEstablished
    handle ignoreIOErr $ do
        tls13 <- tls13orLater ctx
        if tls13
            then do
                when (established == EarlyDataSending) $ clearTxRecordState ctx
                when (tlserror /= Error_TCP_Terminate) $
                    sendPacket13 ctx $
                        Alert13 [errorToAlert tlserror]
            else sendPacket12 ctx $ Alert [errorToAlert tlserror]
    handshakeFailed tlserror
  where
    ignoreIOErr :: IOException -> IO ()
    ignoreIOErr _ = return ()

errorToAlert :: TLSError -> (AlertLevel, AlertDescription)
errorToAlert (Error_Protocol _ ad) = (AlertLevel_Fatal, ad)
errorToAlert (Error_Protocol_Warning _ ad) = (AlertLevel_Warning, ad)
errorToAlert (Error_Packet_unexpected _ _) = (AlertLevel_Fatal, UnexpectedMessage)
errorToAlert (Error_Packet_Parsing msg)
    | "invalid version" `isInfixOf` msg = (AlertLevel_Fatal, ProtocolVersion)
    | "request_update" `isInfixOf` msg = (AlertLevel_Fatal, IllegalParameter)
    | otherwise = (AlertLevel_Fatal, DecodeError)
errorToAlert _ = (AlertLevel_Fatal, InternalError)

-- | Return the message that a TLS endpoint can add to its local log for the
-- specified library error.
errorToAlertMessage :: TLSError -> String
errorToAlertMessage (Error_Protocol msg _) = msg
errorToAlertMessage (Error_Protocol_Warning msg _) = msg
errorToAlertMessage (Error_Packet_unexpected msg _) = msg
errorToAlertMessage (Error_Packet_Parsing msg) = msg
errorToAlertMessage e = show e

unexpected :: MonadIO m => String -> Maybe String -> m a
unexpected msg expected =
    throwCore $ Error_Packet_unexpected msg (maybe "" (" expected: " ++) expected)

newSession :: Context -> IO Session
newSession ctx
    | supportedSession $ ctxSupported ctx = Session . Just <$> getStateRNG ctx 32
    | otherwise = return $ Session Nothing

-- | when a new handshake is done, wrap up & clean up.
handshakeDone12 :: Context -> IO ()
handshakeDone12 ctx = do
    -- forget most handshake data and reset bytes counters.
    modifyMVar_ (ctxHandshakeState ctx) $ \case
        Nothing -> return Nothing
        Just hshake ->
            return $
                Just
                    (newEmptyHandshake (hstClientVersion hshake) (hstClientRandom hshake))
                        { hstServerRandom = hstServerRandom hshake
                        , hstMainSecret = hstMainSecret hshake
                        , hstExtendedMainSecret = hstExtendedMainSecret hshake
                        , hstSupportedGroup = hstSupportedGroup hshake
                        }
    updateMeasure ctx resetBytesCounters
    -- mark the secure connection up and running.
    setEstablished ctx Established
    return ()

sendCCSandFinished
    :: Context
    -> Role
    -> IO ()
sendCCSandFinished ctx role = do
    sendPacket12 ctx ChangeCipherSpec
    contextFlush ctx
    enablePeerRecordLimit ctx
    verifyData <-
        VerifyData
            <$> ( usingState_ ctx getVersion >>= \ver -> usingHState ctx $ getHandshakeDigest ver role
                )
    sendPacket12 ctx (Handshake [Finished verifyData])
    usingState_ ctx $ setVerifyDataForSend verifyData
    contextFlush ctx

data RecvState m
    = RecvStatePacket (Packet -> m (RecvState m)) -- CCS is not Handshake
    | RecvStateHandshake (Handshake -> m (RecvState m))
    | RecvStateDone

recvPacketHandshake :: Context -> IO [Handshake]
recvPacketHandshake ctx = do
    pkts <- recvPacket12 ctx
    case pkts of
        Right (Handshake l) -> return l
        Right x@(AppData _) -> do
            -- If a TLS13 server decides to reject RTT0 data, the server should
            -- skip records for RTT0 data up to the maximum limit.
            established <- ctxEstablished ctx
            case established of
                EarlyDataNotAllowed n
                    | n > 0 -> do
                        setEstablished ctx $ EarlyDataNotAllowed (n - 1)
                        recvPacketHandshake ctx
                _ -> unexpected (show x) (Just "handshake")
        Right x -> unexpected (show x) (Just "handshake")
        Left err -> throwCore err

-- | process a list of handshakes message in the recv state machine.
onRecvStateHandshake
    :: Context -> RecvState IO -> [Handshake] -> IO (RecvState IO)
onRecvStateHandshake _ recvState [] = return recvState
onRecvStateHandshake _ (RecvStatePacket f) hms = f (Handshake hms)
onRecvStateHandshake ctx (RecvStateHandshake f) (x : xs) = do
    let finished = isFinished x
    unless finished $ processHandshake12 ctx x
    nstate <- f x
    when finished $ processHandshake12 ctx x
    onRecvStateHandshake ctx nstate xs
onRecvStateHandshake _ RecvStateDone _xs = unexpected "spurious handshake" Nothing

isFinished :: Handshake -> Bool
isFinished Finished{} = True
isFinished _ = False

runRecvState :: Context -> RecvState IO -> IO ()
runRecvState _ RecvStateDone = return ()
runRecvState ctx (RecvStatePacket f) = recvPacket12 ctx >>= either throwCore f >>= runRecvState ctx
runRecvState ctx iniState =
    recvPacketHandshake ctx
        >>= onRecvStateHandshake ctx iniState
        >>= runRecvState ctx

runRecvStateHS :: Context -> RecvState IO -> [Handshake] -> IO ()
runRecvStateHS ctx iniState hs = onRecvStateHandshake ctx iniState hs >>= runRecvState ctx

ensureRecvComplete :: MonadIO m => Context -> m ()
ensureRecvComplete ctx = do
    complete <- liftIO $ isRecvComplete ctx
    unless complete $
        throwCore $
            Error_Protocol "received incomplete message at key change" UnexpectedMessage

processExtendedMainSecret
    :: MonadIO m => Context -> Version -> MessageType -> [ExtensionRaw] -> m Bool
processExtendedMainSecret ctx ver msgt exts
    | ver < TLS10 = return False
    | ver > TLS12 = error "EMS processing is not compatible with TLS 1.3"
    | ems == NoEMS = return False
    | otherwise =
        liftIO $
            lookupAndDecodeAndDo
                EID_ExtendedMainSecret
                msgt
                exts
                nonExistAction
                existAction
  where
    ems = supportedExtendedMainSecret $ ctxSupported ctx
    err = "peer does not support Extended Main Secret"
    nonExistAction =
        if ems == RequireEMS
            then throwCore $ Error_Protocol err HandshakeFailure
            else return False
    existAction ExtendedMainSecret = do
        usingHState ctx $ setExtendedMainSecret True
        return True

getSessionData :: Context -> IO (Maybe SessionData)
getSessionData ctx = do
    ver <- usingState_ ctx getVersion
    sni <- usingState_ ctx getClientSNI
    mms <- usingHState ctx $ gets hstMainSecret
    ems <- usingHState ctx getExtendedMainSecret
    cipher <- cipherID <$> usingHState ctx getPendingCipher
    alpn <- usingState_ ctx getNegotiatedProtocol
    let compression = 0
        flags = [SessionEMS | ems]
    case mms of
        Nothing -> return Nothing
        Just ms ->
            return $
                Just
                    SessionData
                        { sessionVersion = ver
                        , sessionCipher = cipher
                        , sessionCompression = compression
                        , sessionClientSNI = sni
                        , sessionSecret = ms
                        , sessionGroup = Nothing
                        , sessionTicketInfo = Nothing
                        , sessionALPN = alpn
                        , sessionMaxEarlyDataSize = 0
                        , sessionFlags = flags
                        }

-- | Store the specified keypair.  Whether the public key and private key
-- actually match is left for the peer to discover.  We're not presently
-- burning  CPU to detect that misconfiguration.  We verify only that the
-- types of keys match and that it does not include an algorithm that would
-- not be safe.
storePrivInfo
    :: MonadIO m
    => Context
    -> CertificateChain
    -> PrivKey
    -> m PubKey
storePrivInfo ctx cc privkey = do
    let c = fromCC cc
        pubkey = certPubKey $ getCertificate c
    unless (isDigitalSignaturePair (pubkey, privkey)) $
        throwCore $
            Error_Protocol "mismatched or unsupported private key pair" InternalError
    usingHState ctx $ setPublicPrivateKeys (pubkey, privkey)
    return pubkey
  where
    fromCC (CertificateChain (c : _)) = c
    fromCC _ = error "fromCC"

-- verify that the group selected by the peer is supported in the local
-- configuration
checkSupportedGroup :: Context -> Group -> IO ()
checkSupportedGroup ctx grp =
    unless (isSupportedGroup ctx grp) $
        let msg = "unsupported (EC)DHE group: " ++ show grp
         in throwCore $ Error_Protocol msg IllegalParameter

isSupportedGroup :: Context -> Group -> Bool
isSupportedGroup ctx grp = grp `elem` supportedGroups (ctxSupported ctx)

ensureNullCompression :: MonadIO m => CompressionID -> m ()
ensureNullCompression compression =
    when (compression /= compressionID nullCompression) $
        throwCore $
            Error_Protocol "compression is not allowed in TLS 1.3" IllegalParameter

expectFinished :: Context -> Handshake -> IO (RecvState IO)
expectFinished ctx (Finished verifyData) = do
    processFinished ctx verifyData
    return RecvStateDone
expectFinished _ p = unexpected (show p) (Just "Handshake Finished")

processFinished :: Context -> VerifyData -> IO ()
processFinished ctx verifyData = do
    (cc, ver) <- usingState_ ctx $ (,) <$> getRole <*> getVersion
    expected <-
        VerifyData <$> usingHState ctx (getHandshakeDigest ver $ invertRole cc)
    when (expected /= verifyData) $ decryptError "finished verification failed"
    usingState_ ctx $ setVerifyDataForRecv verifyData

processCertificate :: Context -> Role -> CertificateChain -> IO ()
processCertificate _ ServerRole (CertificateChain []) = return ()
processCertificate _ ClientRole (CertificateChain []) =
    throwCore $ Error_Protocol "server certificate missing" HandshakeFailure
processCertificate ctx _ (CertificateChain (c : _)) =
    usingHState ctx $ setPublicKey pubkey
  where
    pubkey = certPubKey $ getCertificate c

-- TLS 1.2 distinguishes session ID and session ticket.  session
-- ticket. Session ticket is prioritized over session ID.
ticketOrSessionID12
    :: Maybe Ticket -> Session -> Maybe SessionIDorTicket
ticketOrSessionID12 (Just ticket) _
    | ticket /= "" = Just $ B.copy ticket
ticketOrSessionID12 _ (Session (Just sessionId)) = Just $ B.copy sessionId
ticketOrSessionID12 _ _ = Nothing

setPeerRecordSizeLimit :: Context -> Bool -> RecordSizeLimit -> IO ()
setPeerRecordSizeLimit ctx tls13 (RecordSizeLimit n0) = do
    when (n0 < 64) $
        throwCore $
            Error_Protocol ("too small recode size limit: " ++ show n0) IllegalParameter

    -- RFC 8449 Section 4:
    -- Even if a larger record size limit is provided by a peer, an
    -- endpoint MUST NOT send records larger than the protocol-defined
    -- limit, unless explicitly allowed by a future TLS version or
    -- extension.
    let n1 = fromIntegral n0
        n2
            | n1 > protolim = protolim
            | otherwise = n1
    -- Even if peer's value is larger than the protocol-defined
    -- limitation, call "setPeerRecordLimit" to send
    -- "record_size_limit" as ACK.  In this case, the protocol-defined
    -- limitation is used.
    let lim = if tls13 then n2 - 1 else n2
    setPeerRecordLimit ctx $ Just lim
  where
    protolim
        | tls13 = defaultRecordSizeLimit + 1
        | otherwise = defaultRecordSizeLimit
