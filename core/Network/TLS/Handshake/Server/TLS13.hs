{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.TLS.Handshake.Server.TLS13 (
    recvClientSecondFlight13,
    postHandshakeAuthServerWith,
) where

import Control.Monad.State.Strict
import Data.Maybe (fromJust)

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Extension
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.Server.Common
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.Parameters
import Network.TLS.Session
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types
import Network.TLS.X509

recvClientSecondFlight13
    :: ServerParams
    -> Context
    -> ( SecretTriple ApplicationSecret
       , ClientTrafficSecret HandshakeSecret
       , Bool
       , Bool
       )
    -> CH
    -> IO ()
recvClientSecondFlight13 sparams ctx (appKey, clientHandshakeSecret, authenticated, rtt0OK) CH{..} = do
    sfSentTime <- getCurrentTimeFromBase
    let expectFinished' =
            expectFinished sparams ctx chExtensions appKey clientHandshakeSecret sfSentTime
    if not authenticated && serverWantClientCert sparams
        then runRecvHandshake13 $ do
            skip <- recvHandshake13 ctx $ expectCertificate sparams ctx
            unless skip $ recvHandshake13hash ctx (expectCertVerify sparams ctx)
            recvHandshake13hash ctx expectFinished'
            ensureRecvComplete ctx
        else
            if rtt0OK && not (ctxQUICMode ctx)
                then
                    setPendingActions
                        ctx
                        [ PendingAction True $ expectEndOfEarlyData ctx clientHandshakeSecret
                        , PendingActionHash True $
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
    (usedHash, usedCipher, _, _) <- getRxState ctx
    let ClientTrafficSecret chs = clientHandshakeSecret
    checkFinished ctx usedHash chs hChBeforeCf verifyData
    handshakeDone13 ctx
    setRxState ctx usedHash usedCipher clientApplicationSecret0
    sendNewSessionTicket sparams ctx usedCipher exts applicationSecret sfSentTime
  where
    applicationSecret = triBase appKey
    clientApplicationSecret0 = triClient appKey
expectFinished _ _ _ _ _ _ _ hs = unexpected (show hs) (Just "finished 13")

expectEndOfEarlyData
    :: Context -> ClientTrafficSecret HandshakeSecret -> Handshake13 -> IO ()
expectEndOfEarlyData ctx clientHandshakeSecret EndOfEarlyData13 = do
    (usedHash, usedCipher, _, _) <- getRxState ctx
    setRxState ctx usedHash usedCipher clientHandshakeSecret
expectEndOfEarlyData _ _ hs = unexpected (show hs) (Just "end of early data")

expectCertificate
    :: MonadIO m => ServerParams -> Context -> Handshake13 -> m Bool
expectCertificate sparams ctx (Certificate13 certCtx certs _ext) = liftIO $ do
    when (certCtx /= "") $
        throwCore $
            Error_Protocol "certificate request context MUST be empty" IllegalParameter
    -- fixme checking _ext
    clientCertificate sparams ctx certs
    return $ isNullCertificateChain certs
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
    resumptionMasterSecret <- calculateResumptionSecret ctx choice applicationSecret
    let life = toSeconds $ serverTicketLifetime sparams
        psk = derivePSK choice resumptionMasterSecret nonce
    (label, add) <- generateSession life psk rtt0max rtt
    let nst = createNewSessionTicket life add nonce label rtt0max
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
        sessionEstablish mgr sessionId sdata
        return (sessionId, ageAdd tinfo)

    createNewSessionTicket life add nonce label maxSize =
        NewSessionTicket13 life add nonce label extensions
      where
        tedi = extensionEncode $ EarlyDataIndication $ Just $ fromIntegral maxSize
        extensions = [ExtensionRaw EID_EarlyData tedi]
    toSeconds i
        | i < 0 = 0
        | i > 604800 = 604800
        | otherwise = fromIntegral i

expectCertVerify
    :: MonadIO m => ServerParams -> Context -> ByteString -> Handshake13 -> m ()
expectCertVerify sparams ctx hChCc (CertVerify13 sigAlg sig) = liftIO $ do
    certs@(CertificateChain cc) <-
        checkValidClientCertChain ctx "finished 13 message expected"
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

postHandshakeAuthServerWith :: ServerParams -> Context -> Handshake13 -> IO ()
postHandshakeAuthServerWith sparams ctx h@(Certificate13 certCtx certs _ext) = do
    mCertReq <- getCertRequest13 ctx certCtx
    when (isNothing mCertReq) $
        throwCore $
            Error_Protocol "unknown certificate request context" DecodeError
    let certReq = fromJust mCertReq

    -- fixme checking _ext
    clientCertificate sparams ctx certs

    baseHState <- saveHState ctx
    processHandshake13 ctx certReq
    processHandshake13 ctx h

    (usedHash, _, level, applicationSecretN) <- getRxState ctx
    unless (level == CryptApplicationSecret) $
        throwCore $
            Error_Protocol
                "tried post-handshake authentication without application traffic secret"
                InternalError

    let expectFinished' hChBeforeCf (Finished13 verifyData) = do
            checkFinished ctx usedHash applicationSecretN hChBeforeCf verifyData
            void $ restoreHState ctx baseHState
        expectFinished' _ hs = unexpected (show hs) (Just "finished 13")

    -- Note: here the server could send updated NST too, however the library
    -- currently has no API to handle resumption and client authentication
    -- together, see discussion in #133
    if isNullCertificateChain certs
        then setPendingActions ctx [PendingActionHash False expectFinished']
        else
            setPendingActions
                ctx
                [ PendingActionHash False (expectCertVerify sparams ctx)
                , PendingActionHash False expectFinished'
                ]
postHandshakeAuthServerWith _ _ _ =
    throwCore $
        Error_Protocol
            "unexpected handshake message received in postHandshakeAuthServerWith"
            UnexpectedMessage
