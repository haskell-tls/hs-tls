{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Network.TLS.Handshake.Server
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
module Network.TLS.Handshake.Server (
    handshakeServer,
    handshakeServerWith,
    requestCertificateServer,
    postHandshakeAuthServerWith,
) where

import Control.Exception (bracket)
import Control.Monad.State.Strict
import qualified Data.ByteString as B
import Data.Maybe (fromJust)
import Data.X509 (ExtKeyUsageFlag (..))

import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Context.Internal
import Network.TLS.Credentials
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Certificate
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Control
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.Random
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.Measurement
import Network.TLS.Parameters
import Network.TLS.Session
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types
import Network.TLS.Util (bytesEq, catchException)
import Network.TLS.X509

-- Put the server context in handshake mode.
--
-- Expect to receive as first packet a client hello handshake message
--
-- This is just a helper to pop the next message from the recv layer,
-- and call handshakeServerWith.
handshakeServer :: ServerParams -> Context -> IO ()
handshakeServer sparams ctx = liftIO $ do
    hss <- recvPacketHandshake ctx
    case hss of
        [ch] -> handshakeServerWith sparams ctx ch
        _ -> unexpected (show hss) (Just "client hello")

-- | Put the server context in handshake mode.
--
-- Expect a client hello message as parameter.
-- This is useful when the client hello has been already poped from the recv layer to inspect the packet.
--
-- When the function returns, a new handshake has been succesfully negociated.
-- On any error, a HandshakeFailed exception is raised.
--
-- handshake protocol (<- receiving, -> sending, [] optional):
--    (no session)           (session resumption)
--      <- client hello       <- client hello
--      -> server hello       -> server hello
--      -> [certificate]
--      -> [server key xchg]
--      -> [cert request]
--      -> hello done
--      <- [certificate]
--      <- client key xchg
--      <- [cert verify]
--      <- change cipher      -> change cipher
--      <- finish             -> finish
--      -> change cipher      <- change cipher
--      -> finish             <- finish
handshakeServerWith :: ServerParams -> Context -> Handshake -> IO ()
handshakeServerWith sparams ctx clientHello@(ClientHello legacyVersion _ clientSession ciphers compressions exts _) = do
    established <- ctxEstablished ctx
    -- renego is not allowed in TLS 1.3
    when (established /= NotEstablished) $ do
        ver <- usingState_ ctx (getVersionWithDefault TLS12)
        when (ver == TLS13) $
            throwCore $
                Error_Protocol "renegotiation is not allowed in TLS 1.3" UnexpectedMessage
    -- rejecting client initiated renegotiation to prevent DOS.
    eof <- ctxEOF ctx
    let renegotiation = established == Established && not eof
    when
        ( renegotiation && not (supportedClientInitiatedRenegotiation $ ctxSupported ctx)
        )
        $ throwCore
        $ Error_Protocol_Warning "renegotiation is not allowed" NoRenegotiation
    -- check if policy allow this new handshake to happens
    handshakeAuthorized <- withMeasure ctx (onNewHandshake $ serverHooks sparams)
    unless
        handshakeAuthorized
        (throwCore $ Error_HandshakePolicy "server: handshake denied")
    updateMeasure ctx incrementNbHandshakes

    -- Handle Client hello
    processHandshake ctx clientHello

    -- rejecting SSL2. RFC 6176
    when (legacyVersion == SSL2) $
        throwCore $
            Error_Protocol "SSL 2.0 is not supported" ProtocolVersion
    -- rejecting SSL. RFC 7568
    when (legacyVersion == SSL3) $
        throwCore $
            Error_Protocol "SSL 3.0 is not supported" ProtocolVersion

    -- Fallback SCSV: RFC7507
    -- TLS_FALLBACK_SCSV: {0x56, 0x00}
    when
        ( supportedFallbackScsv (ctxSupported ctx)
            && (0x5600 `elem` ciphers)
            && legacyVersion < TLS12
        )
        $ throwCore
        $ Error_Protocol "fallback is not allowed" InappropriateFallback
    -- choosing TLS version
    let clientVersions = case extensionLookup EID_SupportedVersions exts
            >>= extensionDecode MsgTClientHello of
            Just (SupportedVersionsClientHello vers) -> vers -- fixme: vers == []
            _ -> []
        clientVersion = min TLS12 legacyVersion
        serverVersions
            | renegotiation = filter (< TLS13) (supportedVersions $ ctxSupported ctx)
            | otherwise = supportedVersions $ ctxSupported ctx
        mVersion = debugVersionForced $ serverDebug sparams
    chosenVersion <- case mVersion of
        Just cver -> return cver
        Nothing ->
            if (TLS13 `elem` serverVersions) && clientVersions /= []
                then case findHighestVersionFrom13 clientVersions serverVersions of
                    Nothing ->
                        throwCore $
                            Error_Protocol
                                ("client versions " ++ show clientVersions ++ " is not supported")
                                ProtocolVersion
                    Just v -> return v
                else case findHighestVersionFrom clientVersion serverVersions of
                    Nothing ->
                        throwCore $
                            Error_Protocol
                                ("client version " ++ show clientVersion ++ " is not supported")
                                ProtocolVersion
                    Just v -> return v

    -- SNI (Server Name Indication)
    let serverName = case extensionLookup EID_ServerName exts >>= extensionDecode MsgTClientHello of
            Just (ServerName ns) -> listToMaybe (mapMaybe toHostName ns)
              where
                toHostName (ServerNameHostName hostName) = Just hostName
                toHostName (ServerNameOther _) = Nothing
            _ -> Nothing
    maybe (return ()) (usingState_ ctx . setClientSNI) serverName

    -- TLS version dependent
    if chosenVersion <= TLS12
        then
            handshakeServerWithTLS12
                sparams
                ctx
                chosenVersion
                exts
                ciphers
                serverName
                clientVersion
                compressions
                clientSession
        else do
            mapM_ ensureNullCompression compressions
            -- fixme: we should check if the client random is the same as
            -- that in the first client hello in the case of hello retry.
            handshakeServerWithTLS13
                sparams
                ctx
                chosenVersion
                exts
                ciphers
                serverName
                clientSession
handshakeServerWith _ _ _ =
    throwCore $
        Error_Protocol
            "unexpected handshake message received in handshakeServerWith"
            HandshakeFailure

-- TLS 1.2 or earlier
handshakeServerWithTLS12
    :: ServerParams
    -> Context
    -> Version
    -> [ExtensionRaw]
    -> [CipherID]
    -> Maybe String
    -> Version
    -> [CompressionID]
    -> Session
    -> IO ()
handshakeServerWithTLS12 sparams ctx chosenVersion exts ciphers serverName clientVersion compressions clientSession = do
    extraCreds <- onServerNameIndication (serverHooks sparams) serverName
    let allCreds =
            filterCredentials (isCredentialAllowed chosenVersion exts) $
                extraCreds `mappend` sharedCredentials (ctxShared ctx)

    -- If compression is null, commonCompressions should be [0].
    when (null commonCompressions) $
        throwCore $
            Error_Protocol "no compression in common with the client" HandshakeFailure

    -- When selecting a cipher we must ensure that it is allowed for the
    -- TLS version but also that all its key-exchange requirements
    -- will be met.

    -- Some ciphers require a signature and a hash.  With TLS 1.2 the hash
    -- algorithm is selected from a combination of server configuration and
    -- the client "supported_signatures" extension.  So we cannot pick
    -- such a cipher if no hash is available for it.  It's best to skip this
    -- cipher and pick another one (with another key exchange).

    -- Cipher selection is performed in two steps: first server credentials
    -- are flagged as not suitable for signature if not compatible with
    -- negotiated signature parameters.  Then ciphers are evalutated from
    -- the resulting credentials.

    let possibleGroups = negotiatedGroupsInCommon ctx exts
        possibleECGroups = possibleGroups `intersect` availableECGroups
        possibleFFGroups = possibleGroups `intersect` availableFFGroups
        hasCommonGroupForECDHE = not (null possibleECGroups)
        hasCommonGroupForFFDHE = not (null possibleFFGroups)
        hasCustomGroupForFFDHE = isJust (serverDHEParams sparams)
        canFFDHE = hasCustomGroupForFFDHE || hasCommonGroupForFFDHE
        hasCommonGroup cipher =
            case cipherKeyExchange cipher of
                CipherKeyExchange_DH_Anon -> canFFDHE
                CipherKeyExchange_DHE_RSA -> canFFDHE
                CipherKeyExchange_DHE_DSA -> canFFDHE
                CipherKeyExchange_ECDHE_RSA -> hasCommonGroupForECDHE
                CipherKeyExchange_ECDHE_ECDSA -> hasCommonGroupForECDHE
                _ -> True -- group not used

        -- Ciphers are selected according to TLS version, availability of
        -- (EC)DHE group and credential depending on key exchange.
        cipherAllowed cipher = cipherAllowedForVersion chosenVersion cipher && hasCommonGroup cipher
        selectCipher credentials signatureCredentials = filter cipherAllowed (commonCiphers credentials signatureCredentials)

        (creds, signatureCreds, ciphersFilteredVersion) =
            case chosenVersion of
                TLS12 ->
                    let -- Build a list of all hash/signature algorithms in common between
                        -- client and server.
                        possibleHashSigAlgs = hashAndSignaturesInCommon ctx exts

                        -- Check that a candidate signature credential will be compatible with
                        -- client & server hash/signature algorithms.  This returns Just Int
                        -- in order to sort credentials according to server hash/signature
                        -- preference.  When the certificate has no matching hash/signature in
                        -- 'possibleHashSigAlgs' the result is Nothing, and the credential will
                        -- not be used to sign.  This avoids a failure later in 'decideHashSig'.
                        signingRank cred =
                            case credentialDigitalSignatureKey cred of
                                Just pub -> findIndex (pub `signatureCompatible`) possibleHashSigAlgs
                                Nothing -> Nothing

                        -- Finally compute credential lists and resulting cipher list.
                        --
                        -- We try to keep certificates supported by the client, but
                        -- fallback to all credentials if this produces no suitable result
                        -- (see RFC 5246 section 7.4.2 and RFC 8446 section 4.4.2.2).
                        -- The condition is based on resulting (EC)DHE ciphers so that
                        -- filtering credentials does not give advantage to a less secure
                        -- key exchange like CipherKeyExchange_RSA or CipherKeyExchange_DH_Anon.
                        cltCreds = filterCredentialsWithHashSignatures exts allCreds
                        sigCltCreds = filterSortCredentials signingRank cltCreds
                        sigAllCreds = filterSortCredentials signingRank allCreds
                        cltCiphers = selectCipher cltCreds sigCltCreds
                        allCiphers = selectCipher allCreds sigAllCreds

                        resultTuple =
                            if cipherListCredentialFallback cltCiphers
                                then (allCreds, sigAllCreds, allCiphers)
                                else (cltCreds, sigCltCreds, cltCiphers)
                     in resultTuple
                _ ->
                    let sigAllCreds = filterCredentials (isJust . credentialDigitalSignatureKey) allCreds
                        allCiphers = selectCipher allCreds sigAllCreds
                     in (allCreds, sigAllCreds, allCiphers)

    -- The shared cipherlist can become empty after filtering for compatible
    -- creds, check now before calling onCipherChoosing, which does not handle
    -- empty lists.
    when (null ciphersFilteredVersion) $
        throwCore $
            Error_Protocol "no cipher in common with the client" HandshakeFailure

    let usedCipher = onCipherChoosing (serverHooks sparams) chosenVersion ciphersFilteredVersion

    cred <- case cipherKeyExchange usedCipher of
        CipherKeyExchange_RSA -> return $ credentialsFindForDecrypting creds
        CipherKeyExchange_DH_Anon -> return Nothing
        CipherKeyExchange_DHE_RSA -> return $ credentialsFindForSigning KX_RSA signatureCreds
        CipherKeyExchange_DHE_DSA -> return $ credentialsFindForSigning KX_DSA signatureCreds
        CipherKeyExchange_ECDHE_RSA -> return $ credentialsFindForSigning KX_RSA signatureCreds
        CipherKeyExchange_ECDHE_ECDSA -> return $ credentialsFindForSigning KX_ECDSA signatureCreds
        _ ->
            throwCore $
                Error_Protocol "key exchange algorithm not implemented" HandshakeFailure

    ems <- processExtendedMasterSec ctx chosenVersion MsgTClientHello exts
    resumeSessionData <- case clientSession of
        (Session (Just clientSessionId)) -> do
            let resume = liftIO $ sessionResume (sharedSessionManager $ ctxShared ctx) clientSessionId
            resume >>= validateSession serverName ems
        (Session Nothing) -> return Nothing

    -- Currently, we don't send back EcPointFormats. In this case,
    -- the client chooses EcPointFormat_Uncompressed.
    case extensionLookup EID_EcPointFormats exts
        >>= extensionDecode MsgTClientHello of
        Just (EcPointFormatsSupported fs) -> usingState_ ctx $ setClientEcPointFormatSuggest fs
        _ -> return ()

    doHandshake
        sparams
        cred
        ctx
        chosenVersion
        usedCipher
        usedCompression
        clientSession
        resumeSessionData
        exts
  where
    commonCiphers creds sigCreds = filter ((`elem` ciphers) . cipherID) (getCiphers sparams creds sigCreds)
    commonCompressions =
        compressionIntersectID (supportedCompressions $ ctxSupported ctx) compressions
    usedCompression = head commonCompressions

    validateSession _ _ Nothing = return Nothing
    validateSession sni ems m@(Just sd)
        -- SessionData parameters are assumed to match the local server configuration
        -- so we need to compare only to ClientHello inputs.  Abbreviated handshake
        -- uses the same server_name than full handshake so the same
        -- credentials (and thus ciphers) are available.
        | clientVersion < sessionVersion sd = return Nothing
        | sessionCipher sd `notElem` ciphers = return Nothing
        | sessionCompression sd `notElem` compressions = return Nothing
        | isJust sni && sessionClientSNI sd /= sni = return Nothing
        | ems && not emsSession = return Nothing
        | not ems && emsSession =
            let err = "client resumes an EMS session without EMS"
             in throwCore $ Error_Protocol err HandshakeFailure
        | otherwise = return m
      where
        emsSession = SessionEMS `elem` sessionFlags sd

doHandshake
    :: ServerParams
    -> Maybe Credential
    -> Context
    -> Version
    -> Cipher
    -> Compression
    -> Session
    -> Maybe SessionData
    -> [ExtensionRaw]
    -> IO ()
doHandshake sparams mcred ctx chosenVersion usedCipher usedCompression clientSession resumeSessionData exts = do
    case resumeSessionData of
        Nothing -> do
            handshakeSendServerData
            liftIO $ contextFlush ctx
            -- Receive client info until client Finished.
            recvClientData sparams ctx
            sendChangeCipherAndFinish ctx ServerRole
        Just sessionData -> do
            usingState_ ctx (setSession clientSession True)
            serverhello <- makeServerHello clientSession
            sendPacket ctx $ Handshake [serverhello]
            let masterSecret = sessionSecret sessionData
            usingHState ctx $ setMasterSecret chosenVersion ServerRole masterSecret
            logKey ctx (MasterSecret masterSecret)
            sendChangeCipherAndFinish ctx ServerRole
            recvChangeCipherAndFinish ctx
    handshakeTerminate ctx
  where
    ---
    -- When the client sends a certificate, check whether
    -- it is acceptable for the application.
    --
    ---
    makeServerHello session = do
        srand <-
            serverRandom ctx chosenVersion $ supportedVersions $ serverSupported sparams
        case mcred of
            Just cred -> storePrivInfoServer ctx cred
            _ -> return () -- return a sensible error

        -- in TLS12, we need to check as well the certificates we are sending if they have in the extension
        -- the necessary bits set.
        secReneg <- usingState_ ctx getSecureRenegotiation
        secRengExt <-
            if secReneg
                then do
                    vf <- usingState_ ctx $ do
                        cvf <- getVerifiedData ClientRole
                        svf <- getVerifiedData ServerRole
                        return $ extensionEncode (SecureRenegotiation cvf $ Just svf)
                    return [ExtensionRaw EID_SecureRenegotiation vf]
                else return []
        ems <- usingHState ctx getExtendedMasterSec
        let emsExt
                | ems =
                    let raw = extensionEncode ExtendedMasterSecret
                     in [ExtensionRaw EID_ExtendedMasterSecret raw]
                | otherwise = []
        protoExt <- applicationProtocol ctx exts sparams
        sniExt <- do
            resuming <- usingState_ ctx isSessionResuming
            if resuming
                then return []
                else do
                    msni <- usingState_ ctx getClientSNI
                    case msni of
                        -- RFC6066: In this event, the server SHALL include
                        -- an extension of type "server_name" in the
                        -- (extended) server hello. The "extension_data"
                        -- field of this extension SHALL be empty.
                        Just _ -> return [ExtensionRaw EID_ServerName ""]
                        Nothing -> return []
        let extensions =
                sharedHelloExtensions (serverShared sparams)
                    ++ secRengExt
                    ++ emsExt
                    ++ protoExt
                    ++ sniExt
        usingState_ ctx (setVersion chosenVersion)
        usingHState ctx $
            setServerHelloParameters chosenVersion srand usedCipher usedCompression
        return $
            ServerHello
                chosenVersion
                srand
                session
                (cipherID usedCipher)
                (compressionID usedCompression)
                extensions

    handshakeSendServerData = do
        serverSession <- newSession ctx
        usingState_ ctx (setSession serverSession False)
        serverhello <- makeServerHello serverSession
        -- send ServerHello & Certificate & ServerKeyXchg & CertReq
        let certMsg = case mcred of
                Just (srvCerts, _) -> Certificates srvCerts
                _ -> Certificates $ CertificateChain []
        sendPacket ctx $ Handshake [serverhello, certMsg]

        -- send server key exchange if needed
        skx <- case cipherKeyExchange usedCipher of
            CipherKeyExchange_DH_Anon -> Just <$> generateSKX_DH_Anon
            CipherKeyExchange_DHE_RSA -> Just <$> generateSKX_DHE KX_RSA
            CipherKeyExchange_DHE_DSA -> Just <$> generateSKX_DHE KX_DSA
            CipherKeyExchange_ECDHE_RSA -> Just <$> generateSKX_ECDHE KX_RSA
            CipherKeyExchange_ECDHE_ECDSA -> Just <$> generateSKX_ECDHE KX_ECDSA
            _ -> return Nothing
        maybe (return ()) (sendPacket ctx . Handshake . (: []) . ServerKeyXchg) skx

        -- FIXME we don't do this on a Anonymous server

        -- When configured, send a certificate request with the DNs of all
        -- configured CA certificates.
        --
        -- Client certificates MUST NOT be accepted if not requested.
        --
        when (serverWantClientCert sparams) $ do
            let (certTypes, hashSigs) =
                        let as = supportedHashSignatures $ ctxSupported ctx
                         in (nub $ mapMaybe hashSigToCertType as, as)
                creq =
                    CertRequest
                        certTypes
                        hashSigs
                        (map extractCAname $ serverCACertificates sparams)
            usingHState ctx $ setCertReqSent True
            sendPacket ctx (Handshake [creq])

        -- Send HelloDone
        sendPacket ctx (Handshake [ServerHelloDone])

    setup_DHE = do
        let possibleFFGroups = negotiatedGroupsInCommon ctx exts `intersect` availableFFGroups
        (dhparams, priv, pub) <-
            case possibleFFGroups of
                [] ->
                    let dhparams = fromJust $ serverDHEParams sparams
                     in case findFiniteFieldGroup dhparams of
                            Just g -> do
                                usingHState ctx $ setSupportedGroup g
                                generateFFDHE ctx g
                            Nothing -> do
                                (priv, pub) <- generateDHE ctx dhparams
                                return (dhparams, priv, pub)
                g : _ -> do
                    usingHState ctx $ setSupportedGroup g
                    generateFFDHE ctx g

        let serverParams = serverDHParamsFrom dhparams pub

        usingHState ctx $ setServerDHParams serverParams
        usingHState ctx $ setDHPrivate priv
        return serverParams

    -- Choosing a hash algorithm to sign (EC)DHE parameters
    -- in ServerKeyExchange. Hash algorithm is not suggested by
    -- the chosen cipher suite. So, it should be selected based on
    -- the "signature_algorithms" extension in a client hello.
    -- If RSA is also used for key exchange, this function is
    -- not called.
    decideHashSig pubKey = do
            let hashSigs = hashAndSignaturesInCommon ctx exts
            case filter (pubKey `signatureCompatible`) hashSigs of
                [] -> error ("no hash signature for " ++ pubkeyType pubKey)
                x : _ -> return x

    generateSKX_DHE kxsAlg = do
        serverParams <- setup_DHE
        pubKey <- getLocalPublicKey ctx
        mhashSig <- decideHashSig pubKey
        signed <- digitallySignDHParams ctx serverParams pubKey mhashSig
        case kxsAlg of
            KX_RSA -> return $ SKX_DHE_RSA serverParams signed
            KX_DSA -> return $ SKX_DHE_DSA serverParams signed
            _ ->
                error ("generate skx_dhe unsupported key exchange signature: " ++ show kxsAlg)

    generateSKX_DH_Anon = SKX_DH_Anon <$> setup_DHE

    setup_ECDHE grp = do
        usingHState ctx $ setSupportedGroup grp
        (srvpri, srvpub) <- generateECDHE ctx grp
        let serverParams = ServerECDHParams grp srvpub
        usingHState ctx $ setServerECDHParams serverParams
        usingHState ctx $ setGroupPrivate srvpri
        return serverParams

    generateSKX_ECDHE kxsAlg = do
        let possibleECGroups = negotiatedGroupsInCommon ctx exts `intersect` availableECGroups
        grp <- case possibleECGroups of
            [] -> throwCore $ Error_Protocol "no common group" HandshakeFailure
            g : _ -> return g
        serverParams <- setup_ECDHE grp
        pubKey <- getLocalPublicKey ctx
        mhashSig <- decideHashSig pubKey
        signed <- digitallySignECDHParams ctx serverParams pubKey mhashSig
        case kxsAlg of
            KX_RSA -> return $ SKX_ECDHE_RSA serverParams signed
            KX_ECDSA -> return $ SKX_ECDHE_ECDSA serverParams signed
            _ ->
                error ("generate skx_ecdhe unsupported key exchange signature: " ++ show kxsAlg)

-- create a DigitallySigned objects for DHParams or ECDHParams.

-- | receive Client data in handshake until the Finished handshake.
--
--      <- [certificate]
--      <- client key xchg
--      <- [cert verify]
--      <- change cipher
--      <- finish
recvClientData :: ServerParams -> Context -> IO ()
recvClientData sparams ctx = runRecvState ctx (RecvStateHandshake processClientCertificate)
  where
    processClientCertificate (Certificates certs) = do
        clientCertificate sparams ctx certs

        -- FIXME: We should check whether the certificate
        -- matches our request and that we support
        -- verifying with that certificate.

        return $ RecvStateHandshake processClientKeyExchange
    processClientCertificate p = processClientKeyExchange p

    -- cannot use RecvStateHandshake, as the next message could be a ChangeCipher,
    -- so we must process any packet, and in case of handshake call processHandshake manually.
    processClientKeyExchange (ClientKeyXchg _) = return $ RecvStateNext processCertificateVerify
    processClientKeyExchange p = unexpected (show p) (Just "client key exchange")

    -- Check whether the client correctly signed the handshake.
    -- If not, ask the application on how to proceed.
    --
    processCertificateVerify (Handshake [hs@(CertVerify dsig)]) = do
        processHandshake ctx hs

        certs <- checkValidClientCertChain ctx "change cipher message expected"

        usedVersion <- usingState_ ctx getVersion
        -- Fetch all handshake messages up to now.
        msgs <- usingHState ctx $ B.concat <$> getHandshakeMessages

        pubKey <- usingHState ctx getRemotePublicKey
        checkDigitalSignatureKey usedVersion pubKey

        verif <- checkCertificateVerify ctx usedVersion pubKey msgs dsig
        clientCertVerify sparams ctx certs verif
        return $ RecvStateNext expectChangeCipher
    processCertificateVerify p = do
        chain <- usingHState ctx getClientCertChain
        case chain of
            Just cc
                | isNullCertificateChain cc -> return ()
                | otherwise ->
                    throwCore $ Error_Protocol "cert verify message missing" UnexpectedMessage
            Nothing -> return ()
        expectChangeCipher p

    expectChangeCipher ChangeCipherSpec = do
        return $ RecvStateHandshake expectFinish
    expectChangeCipher p = unexpected (show p) (Just "change cipher")

    expectFinish (Finished _) = return RecvStateDone
    expectFinish p = unexpected (show p) (Just "Handshake Finished")

checkValidClientCertChain
    :: MonadIO m => Context -> String -> m CertificateChain
checkValidClientCertChain ctx errmsg = do
    chain <- usingHState ctx getClientCertChain
    let throwerror = Error_Protocol errmsg UnexpectedMessage
    case chain of
        Nothing -> throwCore throwerror
        Just cc
            | isNullCertificateChain cc -> throwCore throwerror
            | otherwise -> return cc

hashAndSignaturesInCommon
    :: Context -> [ExtensionRaw] -> [HashAndSignatureAlgorithm]
hashAndSignaturesInCommon ctx exts =
    let cHashSigs = case extensionLookup EID_SignatureAlgorithms exts
            >>= extensionDecode MsgTClientHello of
            -- See Section 7.4.1.4.1 of RFC 5246.
            Nothing ->
                [ (HashSHA1, SignatureECDSA)
                , (HashSHA1, SignatureRSA)
                , (HashSHA1, SignatureDSA)
                ]
            Just (SignatureAlgorithms sas) -> sas
        sHashSigs = supportedHashSignatures $ ctxSupported ctx
     in -- The values in the "signature_algorithms" extension
        -- are in descending order of preference.
        -- However here the algorithms are selected according
        -- to server preference in 'supportedHashSignatures'.
        sHashSigs `intersect` cHashSigs

negotiatedGroupsInCommon :: Context -> [ExtensionRaw] -> [Group]
negotiatedGroupsInCommon ctx exts = case extensionLookup EID_SupportedGroups exts
    >>= extensionDecode MsgTClientHello of
    Just (SupportedGroups clientGroups) ->
        let serverGroups = supportedGroups (ctxSupported ctx)
         in serverGroups `intersect` clientGroups
    _ -> []

credentialDigitalSignatureKey :: Credential -> Maybe PubKey
credentialDigitalSignatureKey cred
    | isDigitalSignaturePair keys = Just pubkey
    | otherwise = Nothing
  where
    keys@(pubkey, _) = credentialPublicPrivateKeys cred

filterCredentials :: (Credential -> Bool) -> Credentials -> Credentials
filterCredentials p (Credentials l) = Credentials (filter p l)

filterSortCredentials
    :: Ord a => (Credential -> Maybe a) -> Credentials -> Credentials
filterSortCredentials rankFun (Credentials creds) =
    let orderedPairs = sortOn fst [(rankFun cred, cred) | cred <- creds]
     in Credentials [cred | (Just _, cred) <- orderedPairs]

isCredentialAllowed :: Version -> [ExtensionRaw] -> Credential -> Bool
isCredentialAllowed ver exts cred =
    pubkey `versionCompatible` ver && satisfiesEcPredicate p pubkey
  where
    (pubkey, _) = credentialPublicPrivateKeys cred
    -- ECDSA keys are tested against supported elliptic curves until TLS12 but
    -- not after.  With TLS13, the curve is linked to the signature algorithm
    -- and client support is tested with signatureCompatible13.
    p
        | ver < TLS13 = case extensionLookup EID_SupportedGroups exts
            >>= extensionDecode MsgTClientHello of
            Nothing -> const True
            Just (SupportedGroups sg) -> (`elem` sg)
        | otherwise = const True

-- Filters a list of candidate credentials with credentialMatchesHashSignatures.
--
-- Algorithms to filter with are taken from "signature_algorithms_cert"
-- extension when it exists, else from "signature_algorithms" when clients do
-- not implement the new extension (see RFC 8446 section 4.2.3).
--
-- Resulting credential list can be used as input to the hybrid cipher-and-
-- certificate selection for TLS12, or to the direct certificate selection
-- simplified with TLS13.  As filtering credential signatures with client-
-- advertised algorithms is not supposed to cause negotiation failure, in case
-- of dead end with the subsequent selection process, this process should always
-- be restarted with the unfiltered credential list as input (see fallback
-- certificate chains, described in same RFC section).
--
-- Calling code should not forget to apply constraints of extension
-- "signature_algorithms" to any signature-based key exchange derived from the
-- output credentials.  Respecting client constraints on KX signatures is
-- mandatory but not implemented by this function.
filterCredentialsWithHashSignatures
    :: [ExtensionRaw] -> Credentials -> Credentials
filterCredentialsWithHashSignatures exts =
    case withExt EID_SignatureAlgorithmsCert of
        Just (SignatureAlgorithmsCert sas) -> withAlgs sas
        Nothing ->
            case withExt EID_SignatureAlgorithms of
                Nothing -> id
                Just (SignatureAlgorithms sas) -> withAlgs sas
  where
    withExt extId = extensionLookup extId exts >>= extensionDecode MsgTClientHello
    withAlgs sas = filterCredentials (credentialMatchesHashSignatures sas)

-- returns True if certificate filtering with "signature_algorithms_cert" /
-- "signature_algorithms" produced no ephemeral D-H nor TLS13 cipher (so
-- handshake with lower security)
cipherListCredentialFallback :: [Cipher] -> Bool
cipherListCredentialFallback = all nonDH
  where
    nonDH x = case cipherKeyExchange x of
        CipherKeyExchange_DHE_RSA -> False
        CipherKeyExchange_DHE_DSA -> False
        CipherKeyExchange_ECDHE_RSA -> False
        CipherKeyExchange_ECDHE_ECDSA -> False
        CipherKeyExchange_TLS13 -> False
        _ -> True

storePrivInfoServer :: MonadIO m => Context -> Credential -> m ()
storePrivInfoServer ctx (cc, privkey) = void (storePrivInfo ctx cc privkey)

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
handshakeServerWithTLS13 sparams ctx chosenVersion exts clientCiphers _serverName clientSession = do
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
            Error_Protocol "no cipher in common with the client" HandshakeFailure
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
        Nothing ->
            helloRetryRequest
                sparams
                ctx
                chosenVersion
                usedCipher
                exts
                serverGroups
                clientSession
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
            handshakeTerminate13 ctx
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

helloRetryRequest
    :: ServerParams
    -> Context
    -> Version
    -> Cipher
    -> [ExtensionRaw]
    -> [Group]
    -> Session
    -> IO ()
helloRetryRequest sparams ctx chosenVersion usedCipher exts serverGroups clientSession = do
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
            handshakeServer sparams ctx

findHighestVersionFrom :: Version -> [Version] -> Maybe Version
findHighestVersionFrom clientVersion allowedVersions =
    case filter (clientVersion >=) $ sortOn Down allowedVersions of
        [] -> Nothing
        v : _ -> Just v

-- We filter our allowed ciphers here according to dynamic credential lists.
-- Credentials 'creds' come from server parameters but also SNI callback.
-- When the key exchange requires a signature, we use a
-- subset of this list named 'sigCreds'.  This list has been filtered in order
-- to remove certificates that are not compatible with hash/signature
-- restrictions (TLS 1.2).
getCiphers :: ServerParams -> Credentials -> Credentials -> [Cipher]
getCiphers sparams creds sigCreds = filter authorizedCKE (supportedCiphers $ serverSupported sparams)
  where
    authorizedCKE cipher =
        case cipherKeyExchange cipher of
            CipherKeyExchange_RSA -> canEncryptRSA
            CipherKeyExchange_DH_Anon -> True
            CipherKeyExchange_DHE_RSA -> canSignRSA
            CipherKeyExchange_DHE_DSA -> canSignDSA
            CipherKeyExchange_ECDHE_RSA -> canSignRSA
            CipherKeyExchange_ECDHE_ECDSA -> canSignECDSA
            -- unimplemented: non ephemeral DH & ECDH.
            -- Note, these *should not* be implemented, and have
            -- (for example) been removed in OpenSSL 1.1.0
            --
            CipherKeyExchange_DH_DSA -> False
            CipherKeyExchange_DH_RSA -> False
            CipherKeyExchange_ECDH_ECDSA -> False
            CipherKeyExchange_ECDH_RSA -> False
            CipherKeyExchange_TLS13 -> False -- not reached
    canSignDSA = KX_DSA `elem` signingAlgs
    canSignRSA = KX_RSA `elem` signingAlgs
    canSignECDSA = KX_ECDSA `elem` signingAlgs
    canEncryptRSA = isJust $ credentialsFindForDecrypting creds
    signingAlgs = credentialsListSigningAlgorithms sigCreds

findHighestVersionFrom13 :: [Version] -> [Version] -> Maybe Version
findHighestVersionFrom13 clientVersions serverVersions = case svs `intersect` cvs of
    [] -> Nothing
    v : _ -> Just v
  where
    svs = sortOn Down serverVersions
    cvs = sortOn Down $ filter (>= TLS12) clientVersions

applicationProtocol
    :: Context -> [ExtensionRaw] -> ServerParams -> IO [ExtensionRaw]
applicationProtocol ctx exts sparams = do
    -- ALPN (Application Layer Protocol Negotiation)
    case extensionLookup EID_ApplicationLayerProtocolNegotiation exts
        >>= extensionDecode MsgTClientHello of
        Nothing -> return []
        Just (ApplicationLayerProtocolNegotiation protos) -> do
            case onALPNClientSuggest $ serverHooks sparams of
                Just io -> do
                    proto <- io protos
                    when (proto == "") $
                        throwCore $
                            Error_Protocol "no supported application protocols" NoApplicationProtocol
                    usingState_ ctx $ do
                        setExtensionALPN True
                        setNegotiatedProtocol proto
                    return
                        [ ExtensionRaw
                            EID_ApplicationLayerProtocolNegotiation
                            (extensionEncode $ ApplicationLayerProtocolNegotiation [proto])
                        ]
                _ -> return []

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

clientCertificate :: ServerParams -> Context -> CertificateChain -> IO ()
clientCertificate sparams ctx certs = do
    -- run certificate recv hook
    ctxWithHooks ctx (`hookRecvCertificates` certs)
    -- Call application callback to see whether the
    -- certificate chain is acceptable.
    --
    usage <-
        liftIO $
            catchException
                (onClientCertificate (serverHooks sparams) certs)
                rejectOnException
    case usage of
        CertificateUsageAccept -> verifyLeafKeyUsage [KeyUsage_digitalSignature] certs
        CertificateUsageReject reason -> certificateRejected reason

    -- Remember cert chain for later use.
    --
    usingHState ctx $ setClientCertChain certs

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

newCertReqContext :: Context -> IO CertReqContext
newCertReqContext ctx = getStateRNG ctx 32

requestCertificateServer :: ServerParams -> Context -> IO Bool
requestCertificateServer sparams ctx = do
    tls13 <- tls13orLater ctx
    supportsPHA <- usingState_ ctx getClientSupportsPHA
    let ok = tls13 && supportsPHA
    when ok $ do
        certReqCtx <- newCertReqContext ctx
        let certReq = makeCertRequest sparams ctx certReqCtx
        bracket (saveHState ctx) (restoreHState ctx) $ \_ -> do
            addCertRequest13 ctx certReq
            sendPacket13 ctx $ Handshake13 [certReq]
    return ok

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
