{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.TLS.Handshake.Server.ServerHello13 (
    sendServerHello13,
    sendHRR,
) where

import Control.Monad.State.Strict
import qualified Data.ByteString as B

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
import Network.TLS.Session
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
    -> CHP
    -> Maybe ClientRandom
    -> IO
        ( SecretTriple ApplicationSecret
        , ClientTrafficSecret HandshakeSecret
        , Bool
        , Bool
        )
sendServerHello13 sparams ctx clientKeyShare (usedCipher, usedHash, rtt0) CHP{..} mOuterClientRandom = do
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
    setServerParameter
    -- ALPN is used in choosePSK
    alpnExt <- applicationProtocol ctx chExtensions sparams
    (psk, binderInfo, is0RTTvalid) <- choosePSK
    earlyKey <- calculateEarlySecret ctx choice (Left psk) True
    let earlySecret = pairBase earlyKey
        clientEarlySecret = pairClient earlyKey
    preSharedKeyExt <- checkBinder earlySecret binderInfo
    hrr <- usingState_ ctx getTLS13HRR
    let authenticated = isJust binderInfo
        rtt0OK = authenticated && not hrr && rtt0 && rtt0accept && is0RTTvalid
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
        sendServerHello keyShare preSharedKeyExt
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
    hChSf <- transcriptHash ctx
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
        failOnEitherError $ setServerHelloParameters13 ctx usedCipher

    supportsPHA =
        lookupAndDecode
            EID_PostHandshakeAuth
            MsgTClientHello
            chExtensions
            False
            (\PostHandshakeAuth -> True)

    selectPSK (PreSharedKeyClientHello (PskIdentity identity obfAge : _) bnds@(bnd : _)) = do
        when (null dhModes) $
            throwCore $
                Error_Protocol "no psk_key_exchange_modes extension" MissingExtension
        if PSK_DHE_KE `elem` dhModes
            then do
                let len = sum (map (\x -> B.length x + 1) bnds) + 2
                    mgr = sharedSessionManager $ serverShared sparams
                -- sessionInvalidate is not used for TLS 1.3
                -- because PSK is always changed.
                -- So, identity is not stored in Context.
                msdata <-
                    if rtt0
                        then sessionResumeOnlyOnce mgr identity
                        else sessionResume mgr identity
                case msdata of
                    Just sdata -> do
                        let tinfo = fromJust $ sessionTicketInfo sdata
                            psk = sessionSecret sdata
                        isFresh <- checkFreshness tinfo obfAge
                        (isPSKvalid, is0RTTvalid) <- checkSessionEquality sdata
                        if isPSKvalid && isFresh
                            then return (psk, Just (bnd, 0 :: Int, len), is0RTTvalid)
                            else -- fall back to full handshake
                                return (zero, Nothing, False)
                    _ -> return (zero, Nothing, False)
            else return (zero, Nothing, False)
    selectPSK _ = return (zero, Nothing, False)

    choosePSK =
        lookupAndDecodeAndDo
            EID_PreSharedKey
            MsgTClientHello
            chExtensions
            (return (zero, Nothing, False))
            selectPSK

    checkSessionEquality sdata = do
        msni <- usingState_ ctx getClientSNI
        malpn <- usingState_ ctx getNegotiatedProtocol
        let isSameSNI = sessionClientSNI sdata == msni
            isSameCipher = sessionCipher sdata == cipherID usedCipher
            ciphers = supportedCiphers $ serverSupported sparams
            scid = sessionCipher sdata
            isSameKDF = case findCipher scid ciphers of
                Nothing -> False
                Just c -> cipherHash c == cipherHash usedCipher
            isSameVersion = TLS13 == sessionVersion sdata
            isSameALPN = sessionALPN sdata == malpn
            isPSKvalid = isSameKDF && isSameSNI -- fixme: SNI is not required
            is0RTTvalid = isSameVersion && isSameCipher && isSameALPN
        return (isPSKvalid, is0RTTvalid)

    rtt0max = safeNonNegative32 $ serverEarlyDataSize sparams
    rtt0accept = serverEarlyDataSize sparams > 0

    checkBinder _ Nothing = return []
    checkBinder earlySecret (Just (binder, n, tlen)) = do
        binder' <- makePSKBinder ctx earlySecret usedHash tlen Nothing
        unless (binder == binder') $
            decryptError "PSK binder validation failed"
        return [toExtensionRaw $ PreSharedKeyServerHello $ fromIntegral n]

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

    sendServerHello keyShare preSharedKeyExt = do
        let keyShareExt = toExtensionRaw $ KeyShareServerHello keyShare
            versionExt = toExtensionRaw $ SupportedVersionsServerHello TLS13
            shExtensions = keyShareExt : versionExt : preSharedKeyExt
        if isJust $ mOuterClientRandom
            then do
                srand <- liftIO $ serverRandomECH ctx
                let cipherId = CipherId (cipherID usedCipher)
                    sh = ServerHello13 srand chSession cipherId shExtensions
                suffix <- compulteComfirm ctx usedHash sh "ech accept confirmation"
                let srand' = replaceServerRandomECH srand suffix
                    sh' = ServerHello13 srand' chSession cipherId shExtensions
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
            Handshake13 [certtag "" (TLSCertificateChain certChain) ess]
        liftIO $ usingState_ ctx $ setServerCertificateChain certChain
        hChSc <- transcriptHash ctx
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

        let eeExtensions =
                sharedHelloExtensions (serverShared sparams)
                    ++ catMaybes
                        [ {- 0x00 -} sniExt
                        , {- 0x0a -} groupExt
                        , {- 0x10 -} alpnExt
                        , {- 0x1c -} recodeSizeLimitExt
                        , {- 0x2a -} earlyDataExt
                        ]
        eeExtensions' <-
            liftIO $ onEncryptedExtensionsCreating (serverHooks sparams) eeExtensions
        loadPacket13 ctx $ Handshake13 [EncryptedExtensions13 eeExtensions']

    dhModes =
        lookupAndDecode
            EID_PskKeyExchangeModes
            MsgTClientHello
            chExtensions
            []
            (\(PskKeyExchangeModes ms) -> ms)

    hashSize = hashDigestSize usedHash
    zero = B.replicate hashSize 0

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
    failOnEitherError $ setServerHelloParameters13 ctx usedCipher
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
            usingHState ctx $ updateTranscriptHash13HRR
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
    suffix <- compulteComfirm ctx usedHash hrr "hrr ech accept confirmation"
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
