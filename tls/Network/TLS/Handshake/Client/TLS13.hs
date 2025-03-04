{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.Client.TLS13 (
    recvServerSecondFlight13,
    sendClientSecondFlight13,
    asyncServerHello13,
    postHandshakeAuthClientWith,
) where

import Control.Exception (bracket)
import Control.Monad.State.Strict
import qualified Data.ByteString as B
import Data.IORef

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Client.Common
import Network.TLS.Handshake.Client.ServerHello
import Network.TLS.Handshake.Common hiding (expectFinished)
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Control
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.Handshake.TranscriptHash
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.Parameters
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types
import Network.TLS.X509

----------------------------------------------------------------
----------------------------------------------------------------

recvServerSecondFlight13 :: ClientParams -> Context -> Maybe Group -> IO ()
recvServerSecondFlight13 cparams ctx groupSent = do
    resuming <- prepareSecondFlight13 ctx groupSent
    runRecvHandshake13 $ do
        recvHandshake13 ctx $ expectEncryptedExtensions ctx
        unless resuming $ recvHandshake13 ctx $ expectCertRequest cparams ctx
        recvHandshake13hash ctx "Finished" $ expectFinished cparams ctx

----------------------------------------------------------------

prepareSecondFlight13
    :: Context -> Maybe Group -> IO Bool
prepareSecondFlight13 ctx groupSent = do
    choice <- makeCipherChoice TLS13 <$> usingHState ctx getPendingCipher
    prepareSecondFlight13' ctx groupSent choice

prepareSecondFlight13'
    :: Context
    -> Maybe Group
    -> CipherChoice
    -> IO Bool
prepareSecondFlight13' ctx groupSent choice = do
    (_, hkey, resuming) <- switchToHandshakeSecret
    let clientHandshakeSecret = triClient hkey
        serverHandshakeSecret = triServer hkey
        handSecInfo = HandshakeSecretInfo usedCipher (clientHandshakeSecret, serverHandshakeSecret)
    contextSync ctx $ RecvServerHello handSecInfo
    modifyTLS13State ctx $ \st ->
        st
            { tls13stChoice = choice
            , tls13stHsKey = Just hkey
            }
    return resuming
  where
    usedCipher = cCipher choice
    usedHash = cHash choice

    hashSize = hashDigestSize usedHash

    switchToHandshakeSecret = do
        ensureRecvComplete ctx
        ecdhe <- calcSharedKey
        (earlySecret, resuming) <- makeEarlySecret
        handKey <- calculateHandshakeSecret ctx choice earlySecret ecdhe
        let serverHandshakeSecret = triServer handKey
        setRxRecordState ctx usedHash usedCipher serverHandshakeSecret
        return (usedCipher, handKey, resuming)

    calcSharedKey = do
        serverKeyShare <- do
            mks <- usingState_ ctx getTLS13KeyShare
            case mks of
                Just (KeyShareServerHello ks) -> return ks
                Just _ ->
                    throwCore $ Error_Protocol "invalid key_share value" IllegalParameter
                Nothing ->
                    throwCore $
                        Error_Protocol
                            "key exchange not implemented, expected key_share extension"
                            HandshakeFailure
        let grp = keyShareEntryGroup serverKeyShare
        unless (checkKeyShareKeyLength serverKeyShare) $
            throwCore $
                Error_Protocol "broken key_share" IllegalParameter
        unless (groupSent == Just grp) $
            throwCore $
                Error_Protocol "received incompatible group for (EC)DHE" IllegalParameter
        usingHState ctx $ setSupportedGroup grp
        usingHState ctx getGroupPrivate >>= fromServerKeyShare serverKeyShare

    makeEarlySecret = do
        mEarlySecretPSK <- usingHState ctx getTLS13EarlySecret
        case mEarlySecretPSK of
            Nothing -> return (initEarlySecret choice Nothing, False)
            Just earlySecretPSK@(BaseSecret sec) -> do
                mSelectedIdentity <- usingState_ ctx getTLS13PreSharedKey
                case mSelectedIdentity of
                    Nothing ->
                        return (initEarlySecret choice Nothing, False)
                    Just (PreSharedKeyServerHello 0) -> do
                        unless (B.length sec == hashSize) $
                            throwCore $
                                Error_Protocol
                                    "selected cipher is incompatible with selected PSK"
                                    IllegalParameter
                        usingHState ctx $ setTLS13HandshakeMode PreSharedKey
                        return (earlySecretPSK, True)
                    Just _ ->
                        throwCore $ Error_Protocol "selected identity out of range" IllegalParameter

----------------------------------------------------------------

expectEncryptedExtensions
    :: MonadIO m => Context -> Handshake13 -> m ()
expectEncryptedExtensions ctx (EncryptedExtensions13 eexts) = do
    liftIO $ do
        setALPN ctx MsgTEncryptedExtensions eexts
        modifyTLS13State ctx $ \st -> st{tls13stClientExtensions = eexts}
    st13 <- usingHState ctx getTLS13RTT0Status
    when (st13 == RTT0Sent) $
        case extensionLookup EID_EarlyData eexts of
            Just _ -> do
                usingHState ctx $ setTLS13HandshakeMode RTT0
                usingHState ctx $ setTLS13RTT0Status RTT0Accepted
                liftIO $ modifyTLS13State ctx $ \st -> st{tls13st0RTTAccepted = True}
            Nothing -> do
                usingHState ctx $ setTLS13HandshakeMode PreSharedKey
                usingHState ctx $ setTLS13RTT0Status RTT0Rejected
expectEncryptedExtensions _ p = unexpected (show p) (Just "encrypted extensions")

----------------------------------------------------------------
-- not used in 0-RTT
expectCertRequest
    :: MonadIO m => ClientParams -> Context -> Handshake13 -> RecvHandshake13M m ()
expectCertRequest cparams ctx (CertRequest13 token exts) = do
    processCertRequest13 ctx token exts
    recvHandshake13 ctx $ expectCertAndVerify cparams ctx
expectCertRequest cparams ctx other = do
    usingHState ctx $ do
        setCertReqToken Nothing
        setCertReqCBdata Nothing
    -- setCertReqSigAlgsCert Nothing
    expectCertAndVerify cparams ctx other

processCertRequest13
    :: MonadIO m => Context -> CertReqContext -> [ExtensionRaw] -> m ()
processCertRequest13 ctx token exts = do
    let hsextID = EID_SignatureAlgorithms
    -- caextID = EID_SignatureAlgorithmsCert
    dNames <- canames
    -- The @signature_algorithms@ extension is mandatory.
    hsAlgs <- extalgs hsextID unsighash
    cTypes <- case hsAlgs of
        Just as ->
            let validAs = filter isHashSignatureValid13 as
             in return $ sigAlgsToCertTypes ctx validAs
        Nothing -> throwCore $ Error_Protocol "invalid certificate request" HandshakeFailure
    -- Unused:
    -- caAlgs <- extalgs caextID uncertsig
    let zlib =
            lookupAndDecode
                EID_CompressCertificate
                MsgTClientHello
                exts
                False
                (\(CompressCertificate ccas) -> CCA_Zlib `elem` ccas)
    usingHState ctx $ do
        setCertReqToken $ Just token
        setCertReqCBdata $ Just (cTypes, hsAlgs, dNames)
        setTLS13CertComp zlib
  where
    -- setCertReqSigAlgsCert caAlgs

    canames = case extensionLookup EID_CertificateAuthorities exts of
        Nothing -> return []
        Just ext -> case extensionDecode MsgTCertificateRequest ext of
            Just (CertificateAuthorities names) -> return names
            _ -> throwCore $ Error_Protocol "invalid certificate request" HandshakeFailure
    extalgs extID decons = case extensionLookup extID exts of
        Nothing -> return Nothing
        Just ext -> case extensionDecode MsgTCertificateRequest ext of
            Just e ->
                return $ decons e
            _ -> throwCore $ Error_Protocol "invalid certificate request" HandshakeFailure
    unsighash
        :: SignatureAlgorithms
        -> Maybe [HashAndSignatureAlgorithm]
    unsighash (SignatureAlgorithms a) = Just a

----------------------------------------------------------------
-- not used in 0-RTT
expectCertAndVerify
    :: MonadIO m => ClientParams -> Context -> Handshake13 -> RecvHandshake13M m ()
expectCertAndVerify cparams ctx (Certificate13 _ (CertificateChain_ cc) _) = processCertAndVerify cparams ctx cc
expectCertAndVerify cparams ctx (CompressedCertificate13 _ (CertificateChain_ cc) _) = processCertAndVerify cparams ctx cc
expectCertAndVerify _ _ p = unexpected (show p) (Just "server certificate")

processCertAndVerify
    :: MonadIO m
    => ClientParams -> Context -> CertificateChain -> RecvHandshake13M m ()
processCertAndVerify cparams ctx cc = do
    liftIO $ usingState_ ctx $ setServerCertificateChain cc
    liftIO $ doCertificate cparams ctx cc
    let pubkey = certPubKey $ getCertificate $ getCertificateChainLeaf cc
    ver <- liftIO $ usingState_ ctx getVersion
    checkDigitalSignatureKey ver pubkey
    usingHState ctx $ setPublicKey pubkey
    recvHandshake13hash ctx "CertVerify" $ expectCertVerify ctx pubkey

----------------------------------------------------------------

expectCertVerify
    :: MonadIO m => Context -> PubKey -> TranscriptHash -> Handshake13 -> m ()
expectCertVerify ctx pubkey (TranscriptHash hChSc) (CertVerify13 (DigitallySigned sigAlg sig)) = do
    ok <- checkCertVerify ctx pubkey sigAlg sig hChSc
    unless ok $ decryptError "cannot verify CertificateVerify"
expectCertVerify _ _ _ p = unexpected (show p) (Just "certificate verify")

----------------------------------------------------------------

expectFinished
    :: MonadIO m
    => ClientParams
    -> Context
    -> TranscriptHash
    -> Handshake13
    -> m ()
expectFinished cparams ctx hashValue (Finished13 verifyData) = do
    st <- liftIO $ getTLS13State ctx
    let usedHash = cHash $ tls13stChoice st
        ServerTrafficSecret baseKey = triServer $ fromJust $ tls13stHsKey st
    checkFinished ctx usedHash baseKey hashValue verifyData
    liftIO $ do
        minfo <- contextGetInformation ctx
        case minfo of
            Nothing -> return ()
            Just info -> onServerFinished (clientHooks cparams) info
    liftIO $ modifyTLS13State ctx $ \s -> s{tls13stRecvSF = True}
expectFinished _ _ _ p = unexpected (show p) (Just "server finished")

----------------------------------------------------------------
----------------------------------------------------------------

sendClientSecondFlight13 :: ClientParams -> Context -> IO ()
sendClientSecondFlight13 cparams ctx = do
    st <- getTLS13State ctx
    let choice = tls13stChoice st
        hkey = fromJust $ tls13stHsKey st
        rtt0accepted = tls13st0RTTAccepted st
        eexts = tls13stClientExtensions st
    sendClientSecondFlight13' cparams ctx choice hkey rtt0accepted eexts
    modifyTLS13State ctx $ \s -> s{tls13stSentCF = True}

sendClientSecondFlight13'
    :: ClientParams
    -> Context
    -> CipherChoice
    -> SecretTriple HandshakeSecret
    -> Bool
    -> [ExtensionRaw]
    -> IO ()
sendClientSecondFlight13' cparams ctx choice hkey rtt0accepted eexts = do
    hChSf <- transcriptHash ctx "CH..SF"
    unless (ctxQUICMode ctx) $
        runPacketFlight ctx $
            sendChangeCipherSpec13 ctx
    when (rtt0accepted && not (ctxQUICMode ctx)) $
        sendPacket13 ctx (Handshake13 [EndOfEarlyData13])
    let clientHandshakeSecret = triClient hkey
    setTxRecordState ctx usedHash usedCipher clientHandshakeSecret
    sendClientFlight13 cparams ctx usedHash clientHandshakeSecret
    appKey <- switchToApplicationSecret hChSf
    let applicationSecret = triBase appKey
    setResumptionSecret applicationSecret
    let appSecInfo = ApplicationSecretInfo (triClient appKey, triServer appKey)
    contextSync ctx $ SendClientFinished eexts appSecInfo
    modifyTLS13State ctx $ \st -> st{tls13stHsKey = Nothing}
    finishHandshake13 ctx
    rtt0 <- tls13st0RTT <$> getTLS13State ctx
    when rtt0 $ do
        builder <- tls13stPendingSentData <$> getTLS13State ctx
        modifyTLS13State ctx $ \st -> st{tls13stPendingSentData = id}
        unless rtt0accepted $
            mapM_ (sendPacket13 ctx . AppData13) $
                builder []
  where
    usedCipher = cCipher choice
    usedHash = cHash choice

    switchToApplicationSecret hChSf = do
        ensureRecvComplete ctx
        let handshakeSecret = triBase hkey
        appKey <- calculateApplicationSecret ctx choice handshakeSecret hChSf
        let serverApplicationSecret0 = triServer appKey
        let clientApplicationSecret0 = triClient appKey
        setTxRecordState ctx usedHash usedCipher clientApplicationSecret0
        setRxRecordState ctx usedHash usedCipher serverApplicationSecret0
        return appKey

    setResumptionSecret applicationSecret = do
        resumptionSecret <- calculateResumptionSecret ctx choice applicationSecret
        usingHState ctx $ setTLS13ResumptionSecret resumptionSecret

{- Unused for now
uncertsig :: SignatureAlgorithmsCert
          -> Maybe [HashAndSignatureAlgorithm]
uncertsig (SignatureAlgorithmsCert a) = Just a
-}

sendClientFlight13
    :: ClientParams -> Context -> Hash -> ClientTrafficSecret a -> IO ()
sendClientFlight13 cparams ctx usedHash (ClientTrafficSecret baseKey) = do
    mcc <- clientChain cparams ctx
    runPacketFlight ctx $ do
        case mcc of
            Nothing -> return ()
            Just cc -> do
                reqtoken <- usingHState ctx getCertReqToken
                certComp <- usingHState ctx getTLS13CertComp
                loadClientData13 cc reqtoken certComp
        rawFinished <- makeFinished ctx usedHash baseKey
        loadPacket13 ctx $ Handshake13 [rawFinished]
    when (isJust mcc) $
        modifyTLS13State ctx $
            \st -> st{tls13stSentClientCert = True}
  where
    loadClientData13 chain (Just token) certComp = do
        let (CertificateChain certs) = chain
            certExts = replicate (length certs) []
            cHashSigs = filter isHashSignatureValid13 $ supportedHashSignatures $ ctxSupported ctx
        let certtag = if certComp then CompressedCertificate13 else Certificate13
        loadPacket13 ctx $
            Handshake13 [certtag token (CertificateChain_ chain) certExts]
        case certs of
            [] -> return ()
            _ -> do
                hChSc <- transcriptHash ctx "CH..SC"
                pubKey <- getLocalPublicKey ctx
                sigAlg <-
                    liftIO $ getLocalHashSigAlg ctx signatureCompatible13 cHashSigs pubKey
                vfy <- makeCertVerify ctx pubKey sigAlg hChSc
                loadPacket13 ctx $ Handshake13 [vfy]
    --
    loadClientData13 _ _ _ =
        throwCore $
            Error_Protocol "missing TLS 1.3 certificate request context token" InternalError

----------------------------------------------------------------
----------------------------------------------------------------

postHandshakeAuthClientWith :: ClientParams -> Context -> Handshake13 -> IO ()
postHandshakeAuthClientWith cparams ctx h@(CertRequest13 certReqCtx exts) =
    bracket (saveHState ctx) (restoreHState ctx) $ \_ -> do
        void $ updateTranscriptHash13 ctx h
        processCertRequest13 ctx certReqCtx exts
        (usedHash, _, level, applicationSecretN) <- getTxRecordState ctx
        unless (level == CryptApplicationSecret) $
            throwCore $
                Error_Protocol
                    "unexpected post-handshake authentication request"
                    UnexpectedMessage
        sendClientFlight13
            cparams
            ctx
            usedHash
            (ClientTrafficSecret applicationSecretN)
postHandshakeAuthClientWith _ _ _ =
    throwCore $
        Error_Protocol
            "unexpected handshake message received in postHandshakeAuthClientWith"
            UnexpectedMessage

----------------------------------------------------------------
----------------------------------------------------------------

asyncServerHello13
    :: ClientParams -> Context -> Maybe Group -> Millisecond -> IO ()
asyncServerHello13 cparams ctx groupSent chSentTime = do
    setPendingRecvActions
        ctx
        [ PendingRecvAction True False expectServerHello
        , PendingRecvAction True True (expectEncryptedExtensions ctx)
        , PendingRecvActionHash True expectFinishedAndSet
        ]
  where
    expectServerHello sh = do
        setRTT ctx chSentTime
        processServerHello13 cparams ctx sh
        void $ updateTranscriptHash13 ctx sh -- update by myself
        void $ prepareSecondFlight13 ctx groupSent
    expectFinishedAndSet h sf = do
        expectFinished cparams ctx h sf
        liftIO $
            writeIORef (ctxPendingSendAction ctx) $
                Just $
                    sendClientSecondFlight13 cparams
