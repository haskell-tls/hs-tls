{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.TLS.Handshake.Server.ServerHello13 (
    sendServerHello13,
    sendHRR,
) where

import Control.Monad.State.Strict

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Credentials
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Control
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Random
import Network.TLS.Handshake.Server.Common
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

sendServerHello13
    :: ServerParams
    -> Context
    -> KeyShareEntry
    -> (Cipher, Hash, Bool)
    -> (SecretPair EarlySecret, [ExtensionRaw], Bool, Bool)
    -> CHP
    -> Maybe ClientRandom
    -> IO
        ( SecretTriple ApplicationSecret
        , ClientTrafficSecret HandshakeSecret
        , Bool
        , Bool
        )
sendServerHello13 sparams ctx clientKeyShare (usedCipher, usedHash, rtt0) (earlyKey, preSharedKeyExt, authenticated, is0RTTvalid) CHP{..} mOuterClientRandom = do
    let clientEarlySecret = pairClient earlyKey
        earlySecret = pairBase earlyKey
    -- parse CompressCertificate to check if it is broken here
    let zlib =
            lookupAndDecode
                EID_CompressCertificate
                MsgTClientHello
                chExtensions
                False
                (\(CompressCertificate ccas) -> CCA_Zlib `elem` ccas)

    recodeSizeLimitExt <- processRecordSizeLimit ctx chExtensions True
    enableMyRecordLimit ctx

    newSession ctx >>= \ss -> usingState_ ctx $ do
        setSession ss
        setTLS13ClientSupportsPHA supportsPHA
    usingHState ctx $ do
        setSupportedGroup $ keyShareEntryGroup clientKeyShare
        setOuterClientRandom mOuterClientRandom
    hrr <- usingState_ ctx getTLS13HRR
    alpnExt <- applicationProtocol ctx chExtensions sparams
    setServerParameter
    let rtt0OK = authenticated && not hrr && rtt0 && rtt0accept && is0RTTvalid
    extraCreds <-
        usingState_ ctx getClientSNI >>= onServerNameIndication (serverHooks sparams)
    let p = makeCredentialPredicate TLS13 chExtensions
        allCreds =
            filterCredentials (isCredentialAllowed TLS13 p) $
                extraCreds `mappend` sharedCredentials (ctxShared ctx)
    ----------------------------------------------------------------
    established <- ctxEstablished ctx
    if established /= NotEstablished
        then
            if rtt0OK
                then do
                    usingHState ctx $ setTLS13HandshakeMode RTT0
                    usingHState ctx $ setTLS13RTT0Status RTT0Accepted
                else do
                    usingHState ctx $ setTLS13HandshakeMode PreSharedKey
                    usingHState ctx $ setTLS13RTT0Status RTT0Rejected
        else when authenticated $ usingHState ctx $ setTLS13HandshakeMode PreSharedKey
    -- else : FullHandshake or HelloRetryRequest
    mCredInfo <-
        if authenticated then return Nothing else decideCredentialInfo allCreds
    (ecdhe, keyShare) <- makeServerKeyShare ctx clientKeyShare
    ensureRecvComplete ctx
    (clientHandshakeSecret, handSecret) <- runPacketFlight ctx $ do
        sendServerHello keyShare
        sendChangeCipherSpec13 ctx
        ----------------------------------------------------------------
        handKey <- liftIO $ calculateHandshakeSecret ctx choice earlySecret ecdhe
        let serverHandshakeSecret = triServer handKey
            clientHandshakeSecret = triClient handKey
            handSecret = triBase handKey
        liftIO $ do
            if rtt0OK && not (ctxQUICMode ctx)
                then setRxRecordState ctx usedHash usedCipher clientEarlySecret
                else setRxRecordState ctx usedHash usedCipher clientHandshakeSecret
            setTxRecordState ctx usedHash usedCipher serverHandshakeSecret
            let mEarlySecInfo
                    | rtt0OK = Just $ EarlySecretInfo usedCipher clientEarlySecret
                    | otherwise = Nothing
                handSecInfo = HandshakeSecretInfo usedCipher (clientHandshakeSecret, serverHandshakeSecret)
            contextSync ctx $ SendServerHello chExtensions mEarlySecInfo handSecInfo
        ----------------------------------------------------------------
        liftIO $ enablePeerRecordLimit ctx
        sendExtensions rtt0OK alpnExt recodeSizeLimitExt
        case mCredInfo of
            Nothing -> return ()
            Just (cred, hashSig) -> sendCertAndVerify cred hashSig zlib
        let ServerTrafficSecret shs = serverHandshakeSecret
        rawFinished <- makeFinished ctx usedHash shs
        loadPacket13 ctx $ Handshake13 [rawFinished]
        return (clientHandshakeSecret, handSecret)
    ----------------------------------------------------------------
    hChSf <- transcriptHash ctx "CH..SF"
    appKey <- calculateApplicationSecret ctx choice handSecret hChSf
    let clientApplicationSecret0 = triClient appKey
        serverApplicationSecret0 = triServer appKey
    setTxRecordState ctx usedHash usedCipher serverApplicationSecret0
    let appSecInfo = ApplicationSecretInfo (clientApplicationSecret0, serverApplicationSecret0)
    contextSync ctx $ SendServerFinished appSecInfo
    ----------------------------------------------------------------
    when rtt0OK $ setEstablished ctx (EarlyDataAllowed rtt0max)
    return (appKey, clientHandshakeSecret, authenticated, rtt0OK)
  where
    choice = makeCipherChoice TLS13 usedCipher

    setServerParameter = do
        usingState_ ctx $ setVersion TLS13
        failOnEitherError $ setServerHelloParameters13 ctx usedCipher False

    supportsPHA =
        lookupAndDecode
            EID_PostHandshakeAuth
            MsgTClientHello
            chExtensions
            False
            (\PostHandshakeAuth -> True)

    rtt0max = safeNonNegative32 $ serverEarlyDataSize sparams
    rtt0accept = serverEarlyDataSize sparams > 0

    decideCredentialInfo allCreds = do
        let err =
                throwCore $ Error_Protocol "broken signature_algorithms extension" DecodeError
        cHashSigs <-
            lookupAndDecodeAndDo
                EID_SignatureAlgorithms
                MsgTClientHello
                chExtensions
                err
                (\(SignatureAlgorithms sas) -> return sas)
        -- When deciding signature algorithm and certificate, we try to keep
        -- certificates supported by the client, but fallback to all credentials
        -- if this produces no suitable result (see RFC 5246 section 7.4.2 and
        -- RFC 8446 section 4.4.2.2).
        let sHashSigs = filter isHashSignatureValid13 $ supportedHashSignatures $ ctxSupported ctx
            hashSigs = sHashSigs `intersect` cHashSigs
            cltCreds = filterCredentialsWithHashSignatures chExtensions allCreds
        case credentialsFindForSigning13 hashSigs cltCreds of
            Nothing ->
                case credentialsFindForSigning13 hashSigs allCreds of
                    Nothing -> throwCore $ Error_Protocol "credential not found" HandshakeFailure
                    mcs -> return mcs
            mcs -> return mcs

    sendServerHello keyShare = do
        let keyShareExt = toExtensionRaw $ KeyShareServerHello keyShare
            versionExt = toExtensionRaw $ SupportedVersionsServerHello TLS13
            shExtensions = keyShareExt : versionExt : preSharedKeyExt
        if isJust $ mOuterClientRandom
            then do
                srand <- liftIO $ serverRandomECH ctx
                let cipherId = CipherId (cipherID usedCipher)
                    sh = ServerHello13 srand chSession cipherId shExtensions
                suffix <- computeComfirm ctx usedHash sh "ech accept confirmation"
                let srand' = replaceServerRandomECH srand suffix
                    sh' = ServerHello13 srand' chSession cipherId shExtensions
                usingHState ctx $ setECHAccepted True
                loadPacket13 ctx $ Handshake13 [sh']
            else do
                srand <-
                    liftIO $
                        serverRandom ctx TLS13 $
                            supportedVersions $
                                serverSupported sparams
                let sh = ServerHello13 srand chSession (CipherId (cipherID usedCipher)) shExtensions
                loadPacket13 ctx $ Handshake13 [sh]

    sendCertAndVerify cred@(certChain, _) hashSig zlib = do
        storePrivInfoServer ctx cred
        when (serverWantClientCert sparams) $ do
            let certReqCtx = "" -- this must be zero length here.
                certReq = makeCertRequest sparams ctx certReqCtx True
            loadPacket13 ctx $ Handshake13 [certReq]
            usingHState ctx $ setCertReqSent True

        let CertificateChain cs = certChain
            ess = replicate (length cs) []
        let certtag = if zlib then CompressedCertificate13 else Certificate13
        loadPacket13 ctx $
            Handshake13 [certtag "" (CertificateChain_ certChain) ess]
        liftIO $ usingState_ ctx $ setServerCertificateChain certChain
        hChSc <- transcriptHash ctx "CH..SC"
        pubkey <- getLocalPublicKey ctx
        vrfy <- makeCertVerify ctx pubkey hashSig hChSc
        loadPacket13 ctx $ Handshake13 [vrfy]

    sendExtensions rtt0OK alpnExt recodeSizeLimitExt = do
        msni <- liftIO $ usingState_ ctx getClientSNI
        let sniExt = case msni of
                -- RFC6066: In this event, the server SHALL include
                -- an extension of type "server_name" in the
                -- (extended) server hello. The "extension_data"
                -- field of this extension SHALL be empty.
                Just _ -> Just $ toExtensionRaw $ ServerName []
                Nothing -> Nothing

        mgroup <- usingHState ctx getSupportedGroup
        let serverGroups = supportedGroups (ctxSupported ctx)
            groupExt = case serverGroups of
                [] -> Nothing
                rg : _ -> case mgroup of
                    Nothing -> Nothing
                    Just grp
                        | grp == rg -> Nothing
                        | otherwise -> Just $ toExtensionRaw $ SupportedGroups serverGroups
        let earlyDataExt
                | rtt0OK = Just $ toExtensionRaw $ EarlyDataIndication Nothing
                | otherwise = Nothing

        sendECH <- usingHState ctx getECHEE
        let echExt
                | sendECH =
                    Just $
                        toExtensionRaw $
                            ECHEncryptedExtensions $
                                sharedECHConfig $
                                    serverShared sparams
                | otherwise = Nothing
        let eeExtensions =
                sharedHelloExtensions (serverShared sparams)
                    ++ catMaybes
                        [ {- 0x00 -} sniExt
                        , {- 0x0a -} groupExt
                        , {- 0x10 -} alpnExt
                        , {- 0x1c -} recodeSizeLimitExt
                        , {- 0x2a -} earlyDataExt
                        , {- 0xfe0d -} echExt
                        ]
        eeExtensions' <-
            liftIO $ onEncryptedExtensionsCreating (serverHooks sparams) eeExtensions
        loadPacket13 ctx $ Handshake13 [EncryptedExtensions13 eeExtensions']

credentialsFindForSigning13
    :: [HashAndSignatureAlgorithm]
    -> Credentials
    -> Maybe (Credential, HashAndSignatureAlgorithm)
credentialsFindForSigning13 hss0 creds = loop hss0
  where
    loop [] = Nothing
    loop (hs : hss) = case credentialsFindForSigning13' hs creds of
        Nothing -> loop hss
        Just cred -> Just (cred, hs)

-- See credentialsFindForSigning.
credentialsFindForSigning13'
    :: HashAndSignatureAlgorithm -> Credentials -> Maybe Credential
credentialsFindForSigning13' sigAlg (Credentials l) = find forSigning l
  where
    forSigning cred = case credentialDigitalSignatureKey cred of
        Nothing -> False
        Just pub -> pub `signatureCompatible13` sigAlg

contextSync :: Context -> ServerState -> IO ()
contextSync ctx ctl = case ctxHandshakeSync ctx of
    HandshakeSync _ sync -> sync ctx ctl

----------------------------------------------------------------

sendHRR :: Context -> (Cipher, Hash, c) -> CHP -> Bool -> IO ()
sendHRR ctx (usedCipher, usedHash, _) CHP{..} isEch = do
    twice <- usingState_ ctx getTLS13HRR
    when twice $
        throwCore $
            Error_Protocol "Hello retry not allowed again" HandshakeFailure
    usingState_ ctx $ setTLS13HRR True
    failOnEitherError $ setServerHelloParameters13 ctx usedCipher True
    let clientGroups =
            lookupAndDecode
                EID_SupportedGroups
                MsgTClientHello
                chExtensions
                []
                (\(SupportedGroups gs) -> gs)
        possibleGroups = serverGroups `intersect` clientGroups
    case possibleGroups of
        [] ->
            throwCore $
                Error_Protocol "no group in common with the client for HRR" HandshakeFailure
        g : _ -> do
            hrr <- makeHRR ctx usedCipher usedHash chSession g isEch
            usingHState ctx $ setTLS13HandshakeMode HelloRetryRequest
            runPacketFlight ctx $ do
                loadPacket13 ctx $ Handshake13 [hrr]
                sendChangeCipherSpec13 ctx
  where
    serverGroups = supportedGroups (ctxSupported ctx)

makeHRR
    :: Context -> Cipher -> Hash -> Session -> Group -> Bool -> IO Handshake13
makeHRR _ usedCipher _ chSession g False = return hrr
  where
    keyShareExt = toExtensionRaw $ KeyShareHRR g
    versionExt = toExtensionRaw $ SupportedVersionsServerHello TLS13
    extensions = [keyShareExt, versionExt]
    cipherId = CipherId $ cipherID usedCipher
    hrr = ServerHello13 hrrRandom chSession cipherId extensions
makeHRR ctx usedCipher usedHash chSession g True = do
    suffix <- computeComfirm ctx usedHash hrr "hrr ech accept confirmation"
    let echExt' = toExtensionRaw $ ECHHelloRetryRequest suffix
        extensions' = [keyShareExt, versionExt, echExt']
        hrr' = ServerHello13 hrrRandom chSession cipherId extensions'
    return hrr'
  where
    keyShareExt = toExtensionRaw $ KeyShareHRR g
    versionExt = toExtensionRaw $ SupportedVersionsServerHello TLS13
    echExt = toExtensionRaw $ ECHHelloRetryRequest "\x00\x00\x00\x00\x00\x00\x00\x00"
    extensions = [keyShareExt, versionExt, echExt]
    cipherId = CipherId $ cipherID usedCipher
    hrr = ServerHello13 hrrRandom chSession cipherId extensions
