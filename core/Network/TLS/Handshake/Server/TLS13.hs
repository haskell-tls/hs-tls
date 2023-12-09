{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.Server.TLS13 (
    handshakeServerWithTLS13,
    postHandshakeAuthServerWith,
) where

import Control.Monad.State.Strict
import qualified Data.ByteString as B
import Data.Maybe (fromJust)

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Credentials
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Control
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.Random
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
import Network.TLS.Util (bytesEq)
import Network.TLS.X509

-- TLS 1.3 or later
handshakeServerWithTLS13
    :: ServerParams
    -> Context
    -> Version
    -> [ExtensionRaw]
    -> [CipherID]
    -> Maybe String
    -> Session
    -> IO ()
    -> IO ()
handshakeServerWithTLS13 sparams ctx chosenVersion exts clientCiphers _serverName clientSession acceptHRR = do
    when
        (any (\(ExtensionRaw eid _) -> eid == EID_PreSharedKey) $ init exts)
        $ throwCore
        $ Error_Protocol "extension pre_shared_key must be last" IllegalParameter
    -- Deciding cipher.
    -- The shared cipherlist can become empty after filtering for compatible
    -- creds, check now before calling onCipherChoosing, which does not handle
    -- empty lists.
    when (null ciphersFilteredVersion) $
        throwCore $
            Error_Protocol "no cipher in common with the TLS 1.3 client" HandshakeFailure
    let usedCipher = onCipherChoosing (serverHooks sparams) chosenVersion ciphersFilteredVersion
        usedHash = cipherHash usedCipher
        rtt0 = case extensionLookup EID_EarlyData exts >>= extensionDecode MsgTClientHello of
            Just (EarlyDataIndication _) -> True
            Nothing -> False
    when rtt0 $
        -- mark a 0-RTT attempt before a possible HRR, and before updating the
        -- status again if 0-RTT successful
        setEstablished ctx (EarlyDataNotAllowed 3) -- hardcoding
        -- Deciding key exchange from key shares
    keyShares <- case extensionLookup EID_KeyShare exts of
        Nothing ->
            throwCore $
                Error_Protocol
                    "key exchange not implemented, expected key_share extension"
                    MissingExtension
        Just kss -> case extensionDecode MsgTClientHello kss of
            Just (KeyShareClientHello kses) -> return kses
            Just _ ->
                error "handshakeServerWithTLS13: invalid KeyShare value"
            _ ->
                throwCore $ Error_Protocol "broken key_share" DecodeError
    mshare <- findKeyShare keyShares serverGroups
    case mshare of
        Nothing -> do
            sendHHR
                ctx
                chosenVersion
                usedCipher
                exts
                serverGroups
                clientSession
            acceptHRR
        Just keyShare ->
            doHandshake13
                sparams
                ctx
                chosenVersion
                usedCipher
                exts
                usedHash
                keyShare
                clientSession
                rtt0
  where
    ciphersFilteredVersion = filter ((`elem` clientCiphers) . cipherID) serverCiphers
    serverCiphers =
        filter
            (cipherAllowedForVersion chosenVersion)
            (supportedCiphers $ serverSupported sparams)
    serverGroups = supportedGroups (ctxSupported ctx)

findKeyShare :: [KeyShareEntry] -> [Group] -> IO (Maybe KeyShareEntry)
findKeyShare ks ggs = go ggs
  where
    go [] = return Nothing
    go (g : gs) = case filter (grpEq g) ks of
        [] -> go gs
        [k] -> do
            unless (checkKeyShareKeyLength k) $
                throwCore $
                    Error_Protocol "broken key_share" IllegalParameter
            return $ Just k
        _ -> throwCore $ Error_Protocol "duplicated key_share" IllegalParameter
    grpEq g ent = g == keyShareEntryGroup ent

doHandshake13
    :: ServerParams
    -> Context
    -> Version
    -> Cipher
    -> [ExtensionRaw]
    -> Hash
    -> KeyShareEntry
    -> Session
    -> Bool
    -> IO ()
doHandshake13 sparams ctx chosenVersion usedCipher exts usedHash clientKeyShare clientSession rtt0 = do
    newSession ctx >>= \ss -> usingState_ ctx $ do
        setSession ss False
        setClientSupportsPHA supportsPHA
    usingHState ctx $ setSupportedGroup $ keyShareEntryGroup clientKeyShare
    srand <- setServerParameter
    -- ALPN is used in choosePSK
    protoExt <- applicationProtocol ctx exts sparams
    (psk, binderInfo, is0RTTvalid) <- choosePSK
    earlyKey <- calculateEarlySecret ctx choice (Left psk) True
    let earlySecret = pairBase earlyKey
        clientEarlySecret = pairClient earlyKey
    extensions <- checkBinder earlySecret binderInfo
    hrr <- usingState_ ctx getTLS13HRR
    let authenticated = isJust binderInfo
        rtt0OK = authenticated && not hrr && rtt0 && rtt0accept && is0RTTvalid
    extraCreds <-
        usingState_ ctx getClientSNI >>= onServerNameIndication (serverHooks sparams)
    let allCreds =
            filterCredentials (isCredentialAllowed chosenVersion exts) $
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
                    usingHState ctx $ setTLS13HandshakeMode RTT0
                    usingHState ctx $ setTLS13RTT0Status RTT0Rejected
        else when authenticated $ usingHState ctx $ setTLS13HandshakeMode PreSharedKey
    -- else : FullHandshake or HelloRetryRequest
    mCredInfo <-
        if authenticated then return Nothing else decideCredentialInfo allCreds
    (ecdhe, keyShare) <- makeServerKeyShare ctx clientKeyShare
    ensureRecvComplete ctx
    (clientHandshakeSecret, handSecret) <- runPacketFlight ctx $ do
        sendServerHello keyShare srand extensions
        sendChangeCipherSpec13 ctx
        ----------------------------------------------------------------
        handKey <- liftIO $ calculateHandshakeSecret ctx choice earlySecret ecdhe
        let serverHandshakeSecret = triServer handKey
            clientHandshakeSecret = triClient handKey
            handSecret = triBase handKey
        liftIO $ do
            if rtt0OK && not (ctxQUICMode ctx)
                then setRxState ctx usedHash usedCipher clientEarlySecret
                else setRxState ctx usedHash usedCipher clientHandshakeSecret
            setTxState ctx usedHash usedCipher serverHandshakeSecret
            let mEarlySecInfo
                    | rtt0OK = Just $ EarlySecretInfo usedCipher clientEarlySecret
                    | otherwise = Nothing
                handSecInfo = HandshakeSecretInfo usedCipher (clientHandshakeSecret, serverHandshakeSecret)
            contextSync ctx $ SendServerHello exts mEarlySecInfo handSecInfo
        ----------------------------------------------------------------
        sendExtensions rtt0OK protoExt
        case mCredInfo of
            Nothing -> return ()
            Just (cred, hashSig) -> sendCertAndVerify cred hashSig
        let ServerTrafficSecret shs = serverHandshakeSecret
        rawFinished <- makeFinished ctx usedHash shs
        loadPacket13 ctx $ Handshake13 [rawFinished]
        return (clientHandshakeSecret, handSecret)
    sfSentTime <- getCurrentTimeFromBase
    ----------------------------------------------------------------
    hChSf <- transcriptHash ctx
    appKey <- calculateApplicationSecret ctx choice handSecret hChSf
    let clientApplicationSecret0 = triClient appKey
        serverApplicationSecret0 = triServer appKey
        applicationSecret = triBase appKey
    setTxState ctx usedHash usedCipher serverApplicationSecret0
    let appSecInfo = ApplicationSecretInfo (clientApplicationSecret0, serverApplicationSecret0)
    contextSync ctx $ SendServerFinished appSecInfo
    ----------------------------------------------------------------
    if rtt0OK
        then setEstablished ctx (EarlyDataAllowed rtt0max)
        else
            when (established == NotEstablished) $
                setEstablished ctx (EarlyDataNotAllowed 3) -- hardcoding
    let expectFinished hChBeforeCf (Finished13 verifyData) = liftIO $ do
            let ClientTrafficSecret chs = clientHandshakeSecret
            checkFinished ctx usedHash chs hChBeforeCf verifyData
            handshakeDone13 ctx
            setRxState ctx usedHash usedCipher clientApplicationSecret0
            sendNewSessionTicket applicationSecret sfSentTime
        expectFinished _ hs = unexpected (show hs) (Just "finished 13")

    let expectEndOfEarlyData EndOfEarlyData13 =
            setRxState ctx usedHash usedCipher clientHandshakeSecret
        expectEndOfEarlyData hs = unexpected (show hs) (Just "end of early data")

    if not authenticated && serverWantClientCert sparams
        then runRecvHandshake13 $ do
            skip <- recvHandshake13 ctx expectCertificate
            unless skip $ recvHandshake13hash ctx (expectCertVerify sparams ctx)
            recvHandshake13hash ctx expectFinished
            ensureRecvComplete ctx
        else
            if rtt0OK && not (ctxQUICMode ctx)
                then
                    setPendingActions
                        ctx
                        [ PendingAction True expectEndOfEarlyData
                        , PendingActionHash True expectFinished
                        ]
                else runRecvHandshake13 $ do
                    recvHandshake13hash ctx expectFinished
                    ensureRecvComplete ctx
  where
    choice = makeCipherChoice chosenVersion usedCipher

    setServerParameter = do
        srand <-
            serverRandom ctx chosenVersion $ supportedVersions $ serverSupported sparams
        usingState_ ctx $ setVersion chosenVersion
        failOnEitherError $ usingHState ctx $ setHelloParameters13 usedCipher
        return srand

    supportsPHA = case extensionLookup EID_PostHandshakeAuth exts
        >>= extensionDecode MsgTClientHello of
        Just PostHandshakeAuth -> True
        Nothing -> False

    choosePSK = case extensionLookup EID_PreSharedKey exts
        >>= extensionDecode MsgTClientHello of
        Just (PreSharedKeyClientHello (PskIdentity sessionId obfAge : _) bnds@(bnd : _)) -> do
            when (null dhModes) $
                throwCore $
                    Error_Protocol "no psk_key_exchange_modes extension" MissingExtension
            if PSK_DHE_KE `elem` dhModes
                then do
                    let len = sum (map (\x -> B.length x + 1) bnds) + 2
                        mgr = sharedSessionManager $ serverShared sparams
                    msdata <-
                        if rtt0
                            then sessionResumeOnlyOnce mgr sessionId
                            else sessionResume mgr sessionId
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
        _ -> return (zero, Nothing, False)

    checkSessionEquality sdata = do
        msni <- usingState_ ctx getClientSNI
        malpn <- usingState_ ctx getNegotiatedProtocol
        let isSameSNI = sessionClientSNI sdata == msni
            isSameCipher = sessionCipher sdata == cipherID usedCipher
            ciphers = supportedCiphers $ serverSupported sparams
            isSameKDF = case find (\c -> cipherID c == sessionCipher sdata) ciphers of
                Nothing -> False
                Just c -> cipherHash c == cipherHash usedCipher
            isSameVersion = chosenVersion == sessionVersion sdata
            isSameALPN = sessionALPN sdata == malpn
            isPSKvalid = isSameKDF && isSameSNI -- fixme: SNI is not required
            is0RTTvalid = isSameVersion && isSameCipher && isSameALPN
        return (isPSKvalid, is0RTTvalid)

    rtt0max = safeNonNegative32 $ serverEarlyDataSize sparams
    rtt0accept = serverEarlyDataSize sparams > 0

    checkBinder _ Nothing = return []
    checkBinder earlySecret (Just (binder, n, tlen)) = do
        binder' <- makePSKBinder ctx earlySecret usedHash tlen Nothing
        unless (binder `bytesEq` binder') $
            decryptError "PSK binder validation failed"
        let selectedIdentity = extensionEncode $ PreSharedKeyServerHello $ fromIntegral n
        return [ExtensionRaw EID_PreSharedKey selectedIdentity]

    decideCredentialInfo allCreds = do
        cHashSigs <- case extensionLookup EID_SignatureAlgorithms exts of
            Nothing ->
                throwCore $ Error_Protocol "no signature_algorithms extension" MissingExtension
            Just sa -> case extensionDecode MsgTClientHello sa of
                Nothing ->
                    throwCore $ Error_Protocol "broken signature_algorithms extension" DecodeError
                Just (SignatureAlgorithms sas) -> return sas
        -- When deciding signature algorithm and certificate, we try to keep
        -- certificates supported by the client, but fallback to all credentials
        -- if this produces no suitable result (see RFC 5246 section 7.4.2 and
        -- RFC 8446 section 4.4.2.2).
        let sHashSigs = filter isHashSignatureValid13 $ supportedHashSignatures $ ctxSupported ctx
            hashSigs = sHashSigs `intersect` cHashSigs
            cltCreds = filterCredentialsWithHashSignatures exts allCreds
        case credentialsFindForSigning13 hashSigs cltCreds of
            Nothing ->
                case credentialsFindForSigning13 hashSigs allCreds of
                    Nothing -> throwCore $ Error_Protocol "credential not found" HandshakeFailure
                    mcs -> return mcs
            mcs -> return mcs

    sendServerHello keyShare srand extensions = do
        let serverKeyShare = extensionEncode $ KeyShareServerHello keyShare
            selectedVersion = extensionEncode $ SupportedVersionsServerHello chosenVersion
            extensions' =
                ExtensionRaw EID_KeyShare serverKeyShare
                    : ExtensionRaw EID_SupportedVersions selectedVersion
                    : extensions
            helo = ServerHello13 srand clientSession (cipherID usedCipher) extensions'
        loadPacket13 ctx $ Handshake13 [helo]

    sendCertAndVerify cred@(certChain, _) hashSig = do
        storePrivInfoServer ctx cred
        when (serverWantClientCert sparams) $ do
            let certReqCtx = "" -- this must be zero length here.
                certReq = makeCertRequest sparams ctx certReqCtx
            loadPacket13 ctx $ Handshake13 [certReq]
            usingHState ctx $ setCertReqSent True

        let CertificateChain cs = certChain
            ess = replicate (length cs) []
        loadPacket13 ctx $ Handshake13 [Certificate13 "" certChain ess]
        hChSc <- transcriptHash ctx
        pubkey <- getLocalPublicKey ctx
        vrfy <- makeCertVerify ctx pubkey hashSig hChSc
        loadPacket13 ctx $ Handshake13 [vrfy]

    sendExtensions rtt0OK protoExt = do
        msni <- liftIO $ usingState_ ctx getClientSNI
        let sniExtension = case msni of
                -- RFC6066: In this event, the server SHALL include
                -- an extension of type "server_name" in the
                -- (extended) server hello. The "extension_data"
                -- field of this extension SHALL be empty.
                Just _ -> Just $ ExtensionRaw EID_ServerName ""
                Nothing -> Nothing
        mgroup <- usingHState ctx getSupportedGroup
        let serverGroups = supportedGroups (ctxSupported ctx)
            groupExtension
                | null serverGroups = Nothing
                | maybe True (== head serverGroups) mgroup = Nothing
                | otherwise =
                    Just $
                        ExtensionRaw EID_SupportedGroups $
                            extensionEncode (SupportedGroups serverGroups)
        let earlyDataExtension
                | rtt0OK =
                    Just $
                        ExtensionRaw EID_EarlyData $
                            extensionEncode (EarlyDataIndication Nothing)
                | otherwise = Nothing
        let extensions =
                sharedHelloExtensions (serverShared sparams)
                    ++ catMaybes
                        [ earlyDataExtension
                        , groupExtension
                        , sniExtension
                        ]
                    ++ protoExt
        extensions' <-
            liftIO $ onEncryptedExtensionsCreating (serverHooks sparams) extensions
        loadPacket13 ctx $ Handshake13 [EncryptedExtensions13 extensions']

    sendNewSessionTicket applicationSecret sfSentTime = when sendNST $ do
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
        sendNST = PSK_DHE_KE `elem` dhModes
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

    dhModes = case extensionLookup EID_PskKeyExchangeModes exts
        >>= extensionDecode MsgTClientHello of
        Just (PskKeyExchangeModes ms) -> ms
        Nothing -> []

    expectCertificate :: Handshake13 -> RecvHandshake13M IO Bool
    expectCertificate (Certificate13 certCtx certs _ext) = liftIO $ do
        when (certCtx /= "") $
            throwCore $
                Error_Protocol "certificate request context MUST be empty" IllegalParameter
        -- fixme checking _ext
        clientCertificate sparams ctx certs
        return $ isNullCertificateChain certs
    expectCertificate hs = unexpected (show hs) (Just "certificate 13")

    hashSize = hashDigestSize usedHash
    zero = B.replicate hashSize 0

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

sendHHR
    :: Context
    -> Version
    -> Cipher
    -> [ExtensionRaw]
    -> [Group]
    -> Session
    -> IO ()
sendHHR ctx chosenVersion usedCipher exts serverGroups clientSession = do
    twice <- usingState_ ctx getTLS13HRR
    when twice $
        throwCore $
            Error_Protocol "Hello retry not allowed again" HandshakeFailure
    usingState_ ctx $ setTLS13HRR True
    failOnEitherError $ usingHState ctx $ setHelloParameters13 usedCipher
    let clientGroups = case extensionLookup EID_SupportedGroups exts
            >>= extensionDecode MsgTClientHello of
            Just (SupportedGroups gs) -> gs
            Nothing -> []
        possibleGroups = serverGroups `intersect` clientGroups
    case possibleGroups of
        [] ->
            throwCore $
                Error_Protocol "no group in common with the client for HRR" HandshakeFailure
        g : _ -> do
            let serverKeyShare = extensionEncode $ KeyShareHRR g
                selectedVersion = extensionEncode $ SupportedVersionsServerHello chosenVersion
                extensions =
                    [ ExtensionRaw EID_KeyShare serverKeyShare
                    , ExtensionRaw EID_SupportedVersions selectedVersion
                    ]
                hrr = ServerHello13 hrrRandom clientSession (cipherID usedCipher) extensions
            usingHState ctx $ setTLS13HandshakeMode HelloRetryRequest
            runPacketFlight ctx $ do
                loadPacket13 ctx $ Handshake13 [hrr]
                sendChangeCipherSpec13 ctx

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

    let expectFinished hChBeforeCf (Finished13 verifyData) = do
            checkFinished ctx usedHash applicationSecretN hChBeforeCf verifyData
            void $ restoreHState ctx baseHState
        expectFinished _ hs = unexpected (show hs) (Just "finished 13")

    -- Note: here the server could send updated NST too, however the library
    -- currently has no API to handle resumption and client authentication
    -- together, see discussion in #133
    if isNullCertificateChain certs
        then setPendingActions ctx [PendingActionHash False expectFinished]
        else
            setPendingActions
                ctx
                [ PendingActionHash False (expectCertVerify sparams ctx)
                , PendingActionHash False expectFinished
                ]
postHandshakeAuthServerWith _ _ _ =
    throwCore $
        Error_Protocol
            "unexpected handshake message received in postHandshakeAuthServerWith"
            UnexpectedMessage

contextSync :: Context -> ServerState -> IO ()
contextSync ctx ctl = case ctxHandshakeSync ctx of
    HandshakeSync _ sync -> sync ctx ctl
