{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.TLS.Handshake.Server.TLS13 (
    recvClientSecondFlight13,
    requestCertificateServer,
    keyUpdate,
    updateKey,
    KeyUpdateRequest (..),
) where

import Control.Exception
import Control.Monad.State.Strict
import qualified Data.ByteString.Char8 as C8
import Data.IORef

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Common hiding (expectFinished)
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Server.Common
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.Handshake.TranscriptHash
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.KeySchedule
import Network.TLS.Parameters
import Network.TLS.Session
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types
import Network.TLS.Util
import Network.TLS.X509

----------------------------------------------------------------

recvClientSecondFlight13
    :: ServerParams
    -> Context
    -> ( SecretTriple ApplicationSecret
       , ClientTrafficSecret HandshakeSecret
       , Bool
       , Bool
       )
    -> CHP
    -> IO ()
recvClientSecondFlight13 sparams ctx (appKey, clientHandshakeSecret, authenticated, rtt0OK) CHP{..} = do
    sfSentTime <- getCurrentTimeFromBase
    let expectFinished' =
            expectFinished sparams ctx chExtensions appKey clientHandshakeSecret sfSentTime
    if not authenticated && serverWantClientCert sparams
        then runRecvHandshake13 $ do
            recvHandshake13 ctx $ expectCertificate sparams ctx
            recvHandshake13hash ctx (expectCertVerify sparams ctx)
            recvHandshake13hash ctx expectFinished'
            ensureRecvComplete ctx
        else
            if rtt0OK && not (ctxQUICMode ctx)
                then
                    setPendingRecvActions
                        ctx
                        [ PendingRecvAction True True $ expectEndOfEarlyData ctx clientHandshakeSecret
                        , PendingRecvActionHash True $
                            expectFinished sparams ctx chExtensions appKey clientHandshakeSecret sfSentTime
                        ]
                else runRecvHandshake13 $ do
                    recvHandshake13hash ctx expectFinished'
                    ensureRecvComplete ctx

expectFinished
    :: MonadIO m
    => ServerParams
    -> Context
    -> [ExtensionRaw]
    -> SecretTriple ApplicationSecret
    -> ClientTrafficSecret HandshakeSecret
    -> Word64
    -> ByteString
    -> Handshake13
    -> m ()
expectFinished sparams ctx exts appKey clientHandshakeSecret sfSentTime hChBeforeCf (Finished13 verifyData) = liftIO $ do
    modifyTLS13State ctx $ \st -> st{tls13stRecvCF = True}
    (usedHash, usedCipher, _, _) <- getRxRecordState ctx
    let ClientTrafficSecret chs = clientHandshakeSecret
    checkFinished ctx usedHash chs hChBeforeCf verifyData
    finishHandshake13 ctx
    setRxRecordState ctx usedHash usedCipher clientApplicationSecret0
    sendNewSessionTicket sparams ctx usedCipher exts applicationSecret sfSentTime
  where
    applicationSecret = triBase appKey
    clientApplicationSecret0 = triClient appKey
expectFinished _ _ _ _ _ _ _ hs = unexpected (show hs) (Just "finished 13")

expectEndOfEarlyData
    :: Context -> ClientTrafficSecret HandshakeSecret -> Handshake13 -> IO ()
expectEndOfEarlyData ctx clientHandshakeSecret EndOfEarlyData13 = do
    (usedHash, usedCipher, _, _) <- getRxRecordState ctx
    setRxRecordState ctx usedHash usedCipher clientHandshakeSecret
expectEndOfEarlyData _ _ hs = unexpected (show hs) (Just "end of early data")

expectCertificate
    :: MonadIO m => ServerParams -> Context -> Handshake13 -> m ()
expectCertificate sparams ctx (Certificate13 certCtx (TLSCertificateChain certs) _ext) = liftIO $ do
    when (certCtx /= "") $
        throwCore $
            Error_Protocol "certificate request context MUST be empty" IllegalParameter
    -- fixme checking _ext
    clientCertificate sparams ctx certs
expectCertificate sparams ctx (CompressedCertificate13 certCtx (TLSCertificateChain certs) _ext) = liftIO $ do
    when (certCtx /= "") $
        throwCore $
            Error_Protocol "certificate request context MUST be empty" IllegalParameter
    -- fixme checking _ext
    clientCertificate sparams ctx certs
expectCertificate _ _ hs = unexpected (show hs) (Just "certificate 13")

sendNewSessionTicket
    :: ServerParams
    -> Context
    -> Cipher
    -> [ExtensionRaw]
    -> BaseSecret ApplicationSecret
    -> Word64
    -> IO ()
sendNewSessionTicket sparams ctx usedCipher exts applicationSecret sfSentTime = when sendNST $ do
    cfRecvTime <- getCurrentTimeFromBase
    let rtt = cfRecvTime - sfSentTime
    nonce <- getStateRNG ctx 32
    resumptionSecret <- calculateResumptionSecret ctx choice applicationSecret
    let life = adjustLifetime $ serverTicketLifetime sparams
        psk = derivePSK choice resumptionSecret nonce
    (identity, add) <- generateSession life psk rtt0max rtt
    let nst = createNewSessionTicket life add nonce identity rtt0max
    sendPacket13 ctx $ Handshake13 [nst]
  where
    choice = makeCipherChoice TLS13 usedCipher
    rtt0max = safeNonNegative32 $ serverEarlyDataSize sparams
    sendNST = PSK_DHE_KE `elem` dhModes

    dhModes = case extensionLookup EID_PskKeyExchangeModes exts
        >>= extensionDecode MsgTClientHello of
        Just (PskKeyExchangeModes ms) -> ms
        Nothing -> []

    generateSession life psk maxSize rtt = do
        Session (Just sessionId) <- newSession ctx
        tinfo <- createTLS13TicketInfo life (Left ctx) (Just rtt)
        sdata <- getSessionData13 ctx usedCipher tinfo maxSize psk
        let mgr = sharedSessionManager $ serverShared sparams
        mticket <- sessionEstablish mgr sessionId sdata
        let identity = fromMaybe sessionId mticket
        return (identity, ageAdd tinfo)

    createNewSessionTicket life add nonce identity maxSize =
        NewSessionTicket13 life add nonce identity extensions
      where
        earlyDataExt = toExtensionRaw $ EarlyDataIndication $ Just $ fromIntegral maxSize
        extensions = [earlyDataExt]
    adjustLifetime i
        | i < 0 = 0
        | i > 604800 = 604800
        | otherwise = fromIntegral i

expectCertVerify
    :: MonadIO m => ServerParams -> Context -> ByteString -> Handshake13 -> m ()
expectCertVerify sparams ctx hChCc (CertVerify13 (DigitallySigned sigAlg sig)) = liftIO $ do
    certs@(CertificateChain cc) <-
        checkValidClientCertChain ctx "invalid client certificate chain"
    pubkey <- case cc of
        [] -> throwCore $ Error_Protocol "client certificate missing" HandshakeFailure
        c : _ -> return $ certPubKey $ getCertificate c
    ver <- usingState_ ctx getVersion
    checkDigitalSignatureKey ver pubkey
    usingHState ctx $ setPublicKey pubkey
    verif <- checkCertVerify ctx pubkey sigAlg sig hChCc
    clientCertVerify sparams ctx certs verif
expectCertVerify _ _ _ hs = unexpected (show hs) (Just "certificate verify 13")

clientCertVerify :: ServerParams -> Context -> CertificateChain -> Bool -> IO ()
clientCertVerify sparams ctx certs verif = do
    if verif
        then do
            -- When verification succeeds, commit the
            -- client certificate chain to the context.
            --
            usingState_ ctx $ setClientCertificateChain certs
            return ()
        else do
            -- Either verification failed because of an
            -- invalid format (with an error message), or
            -- the signature is wrong.  In either case,
            -- ask the application if it wants to
            -- proceed, we will do that.
            res <- liftIO $ onUnverifiedClientCert (serverHooks sparams)
            if res
                then do
                    -- When verification fails, but the
                    -- application callbacks accepts, we
                    -- also commit the client certificate
                    -- chain to the context.
                    usingState_ ctx $ setClientCertificateChain certs
                else decryptError "verification failed"

----------------------------------------------------------------

newCertReqContext :: Context -> IO CertReqContext
newCertReqContext ctx = getStateRNG ctx 32

requestCertificateServer :: ServerParams -> Context -> IO Bool
requestCertificateServer sparams ctx = handleEx ctx $ do
    tls13 <- tls13orLater ctx
    supportsPHA <- usingState_ ctx getTLS13ClientSupportsPHA
    let ok = tls13 && supportsPHA
    if ok
        then newIORef [] >>= sendCertReqAndRecv
        else return ok
  where
    sendCertReqAndRecv ref = do
        origCertReqCtx <- newCertReqContext ctx
        let certReq13 = makeCertRequest sparams ctx origCertReqCtx False
        _ <- withWriteLock ctx $ do
            bracket (saveHState ctx) (restoreHState ctx) $ \_ -> do
                sendPacket13 ctx $ Handshake13 [certReq13]
        withReadLock ctx $ do
            clientCert13 <- getHandshake ctx ref
            emptyCert <- expectClientCertificate sparams ctx origCertReqCtx clientCert13
            baseHState <- saveHState ctx
            void $ updateTranscriptHash13 ctx certReq13
            void $ updateTranscriptHash13 ctx clientCert13
            th <- transcriptHash ctx
            unless emptyCert $ do
                certVerify13 <- getHandshake ctx ref
                expectCertVerify sparams ctx th certVerify13
                void $ updateTranscriptHash13 ctx certVerify13
            finished13 <- getHandshake ctx ref
            expectClientFinished ctx finished13
            void $ restoreHState ctx baseHState -- fixme
        return True

-- saving appdata and key update?
-- error handling
getHandshake :: Context -> IORef [Handshake13] -> IO Handshake13
getHandshake ctx ref = do
    hhs <- readIORef ref
    if null hhs
        then do
            ex <- recvPacket13 ctx
            either (terminate ctx) process ex
        else chk hhs
  where
    process (Handshake13 iss) = chk iss
    process _ =
        terminate ctx $
            Error_Protocol "post handshake authenticated" UnexpectedMessage
    chk [] = getHandshake ctx ref
    chk (KeyUpdate13 mode : hs) = do
        keyUpdate ctx getRxRecordState setRxRecordState
        -- Write lock wraps both actions because we don't want another
        -- packet to be sent by another thread before the Tx state is
        -- updated.
        when (mode == UpdateRequested) $ withWriteLock ctx $ do
            sendPacket13 ctx $ Handshake13 [KeyUpdate13 UpdateNotRequested]
            keyUpdate ctx getTxRecordState setTxRecordState
        chk hs
    chk (h : hs) = do
        writeIORef ref hs
        return h

expectClientCertificate
    :: ServerParams -> Context -> CertReqContext -> Handshake13 -> IO Bool
expectClientCertificate sparams ctx origCertReqCtx (Certificate13 certReqCtx (TLSCertificateChain certs) _ext) = do
    expectClientCertificate' sparams ctx origCertReqCtx certReqCtx certs
    return $ isNullCertificateChain certs
expectClientCertificate sparams ctx origCertReqCtx (CompressedCertificate13 certReqCtx (TLSCertificateChain certs) _ext) = do
    expectClientCertificate' sparams ctx origCertReqCtx certReqCtx certs
    return $ isNullCertificateChain certs
expectClientCertificate _ _ _ h = unexpected "Certificate" $ Just $ show h

expectClientCertificate'
    :: ServerParams
    -> Context
    -> CertReqContext
    -> CertReqContext
    -> CertificateChain
    -> IO ()
expectClientCertificate' sparams ctx origCertReqCtx certReqCtx certs = do
    when (origCertReqCtx /= certReqCtx) $
        throwCore $
            Error_Protocol "certificate context is wrong" IllegalParameter
    void $ clientCertificate sparams ctx certs

expectClientFinished :: Context -> Handshake13 -> IO ()
expectClientFinished ctx (Finished13 verifyData) = do
    (usedHash, _, level, applicationSecretN) <- getRxRecordState ctx
    unless (level == CryptApplicationSecret) $
        throwCore $
            Error_Protocol
                "tried post-handshake authentication without application traffic secret"
                InternalError
    hChBeforeCf <- transcriptHash ctx
    checkFinished ctx usedHash applicationSecretN hChBeforeCf verifyData
expectClientFinished _ h = unexpected "Finished" $ Just $ show h

terminate :: Context -> TLSError -> IO a
terminate ctx err = do
    let (level, desc) = errorToAlert err
        reason = errorToAlertMessage err
        send = sendPacket13 ctx . Alert13
    catchException (send [(level, desc)]) (\_ -> return ())
    setEOF ctx
    throwIO $ Terminated False reason err

handleEx :: Context -> IO Bool -> IO Bool
handleEx ctx f = catchException f $ \exception -> do
    -- If the error was an Uncontextualized TLSException, we replace the
    -- context with HandshakeFailed. If it's anything else, we convert
    -- it to a string and wrap it with Error_Misc and HandshakeFailed.
    let tlserror = case fromException exception of
            Just e | Uncontextualized e' <- e -> e'
            _ -> Error_Misc (show exception)
    sendPacket13 ctx $ Alert13 [errorToAlert tlserror]
    void $ throwIO $ PostHandshake tlserror
    return False

----------------------------------------------------------------

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
            keyUpdate ctx getTxRecordState setTxRecordState
    return tls13
