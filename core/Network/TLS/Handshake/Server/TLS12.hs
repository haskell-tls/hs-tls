{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.Server.TLS12 (
    handshakeServerWithTLS12,
) where

import Control.Monad.State.Strict
import qualified Data.ByteString as B
import Data.Maybe (fromJust)

import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Context.Internal
import Network.TLS.Credentials
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Certificate
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.Random
import Network.TLS.Handshake.Server.Common
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.State
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.Parameters
import Network.TLS.Session
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Types
import Network.TLS.X509

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
            Error_Protocol "no cipher in common with the TLS 1.2 client" HandshakeFailure

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
    handshakeDone ctx
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
    processClientKeyExchange (ClientKeyXchg _) = return $ RecvStatePacket processCertificateVerify
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
        return $ RecvStatePacket expectChangeCipher
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

filterSortCredentials
    :: Ord a => (Credential -> Maybe a) -> Credentials -> Credentials
filterSortCredentials rankFun (Credentials creds) =
    let orderedPairs = sortOn fst [(rankFun cred, cred) | cred <- creds]
     in Credentials [cred | (Just _, cred) <- orderedPairs]

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
