{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.TLS.Handshake.Server.ServerHello12 (
    sendServerHello12,
) where

import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Context.Internal
import Network.TLS.Credentials
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Certificate
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Key
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
import Network.TLS.X509 hiding (Certificate)

sendServerHello12
    :: ServerParams
    -> Context
    -> (Cipher, Maybe Credential)
    -> CH
    -> IO (Maybe SessionData)
sendServerHello12 sparams ctx (usedCipher, mcred) ch@CH{..} = do
    resumeSessionData <- recoverSessionData ctx ch
    case resumeSessionData of
        Nothing -> do
            serverSession <- newSession ctx
            usingState_ ctx $ setSession serverSession
            serverhello <-
                makeServerHello sparams ctx usedCipher mcred chExtensions serverSession
            build <- sendServerFirstFlight sparams ctx usedCipher mcred chExtensions
            let ff = serverhello : build [ServerHelloDone]
            sendPacket12 ctx $ Handshake ff
            contextFlush ctx
        Just sessionData -> do
            usingState_ ctx $ do
                setSession chSession
                setTLS12SessionResuming True
            serverhello <-
                makeServerHello sparams ctx usedCipher mcred chExtensions chSession
            sendPacket12 ctx $ Handshake [serverhello]
            let mainSecret = sessionSecret sessionData
            usingHState ctx $ setMainSecret TLS12 ServerRole mainSecret
            logKey ctx $ MainSecret mainSecret
            sendCCSandFinished ctx ServerRole
    return resumeSessionData

recoverSessionData :: Context -> CH -> IO (Maybe SessionData)
recoverSessionData ctx CH{..} = do
    serverName <- usingState_ ctx getClientSNI
    ems <- processExtendedMainSecret ctx TLS12 MsgTClientHello chExtensions
    let mticket =
            lookupAndDecode
                EID_SessionTicket
                MsgTClientHello
                chExtensions
                Nothing
                (\(SessionTicket ticket) -> Just ticket)
        midentity = ticketOrSessionID12 mticket chSession
    case midentity of
        Nothing -> return Nothing
        Just identity -> do
            sd <- sessionResume (sharedSessionManager $ ctxShared ctx) identity
            validateSession ctx chCiphers serverName ems sd

validateSession
    :: Context
    -> [CipherId]
    -> Maybe HostName
    -> Bool
    -> Maybe SessionData
    -> IO (Maybe SessionData)
validateSession _ _ _ _ Nothing = return Nothing
validateSession ctx ciphers sni ems m@(Just sd)
    -- SessionData parameters are assumed to match the local server configuration
    -- so we need to compare only to ClientHello inputs.  Abbreviated handshake
    -- uses the same server_name than full handshake so the same
    -- credentials (and thus ciphers) are available.
    | TLS12 < sessionVersion sd = return Nothing -- fixme
    | CipherId (sessionCipher sd) `notElem` ciphers =
        throwCore $
            Error_Protocol "new cipher is diffrent from the old one" IllegalParameter
    | isJust sni && sessionClientSNI sd /= sni = do
        usingState_ ctx clearClientSNI
        return Nothing
    | ems && not emsSession = return Nothing
    | not ems && emsSession =
        let err = "client resumes an EMS session without EMS"
         in throwCore $ Error_Protocol err HandshakeFailure
    | otherwise = return m
  where
    emsSession = SessionEMS `elem` sessionFlags sd

sendServerFirstFlight
    :: ServerParams
    -> Context
    -> Cipher
    -> Maybe Credential
    -> [ExtensionRaw]
    -> IO ([Handshake] -> [Handshake])
sendServerFirstFlight ServerParams{..} ctx usedCipher mcred chExts = do
    let b0 = id
    let cc = case mcred of
            Just (srvCerts, _) -> srvCerts
            _ -> CertificateChain []
    let b1 = b0 . (Certificate (TLSCertificateChain cc) :)
    usingState_ ctx $ setServerCertificateChain cc

    -- send server key exchange if needed
    skx <- case cipherKeyExchange usedCipher of
        CipherKeyExchange_DH_Anon -> Just <$> generateSKX_DH_Anon
        CipherKeyExchange_DHE_RSA -> Just <$> generateSKX_DHE KX_RSA
        CipherKeyExchange_DHE_DSA -> Just <$> generateSKX_DHE KX_DSA
        CipherKeyExchange_ECDHE_RSA -> Just <$> generateSKX_ECDHE KX_RSA
        CipherKeyExchange_ECDHE_ECDSA -> Just <$> generateSKX_ECDHE KX_ECDSA
        _ -> return Nothing
    let b2 = case skx of
            Nothing -> b1
            Just kx -> b1 . (ServerKeyXchg kx :)

    -- FIXME we don't do this on a Anonymous server

    -- When configured, send a certificate request with the DNs of all
    -- configured CA certificates.
    --
    -- Client certificates MUST NOT be accepted if not requested.
    --
    if serverWantClientCert
        then do
            let (certTypes, hashSigs) =
                    let as = supportedHashSignatures serverSupported
                     in (nub $ mapMaybe hashSigToCertType as, as)
                creq =
                    CertRequest
                        certTypes
                        hashSigs
                        (map extractCAname serverCACertificates)
            usingHState ctx $ setCertReqSent True
            return $ b2 . (creq :)
        else return b2
  where
    commonGroups = negotiatedGroupsInCommon (supportedGroups serverSupported) chExts
    commonHashSigs = hashAndSignaturesInCommon (supportedHashSignatures serverSupported) chExts
    setup_DHE = do
        let possibleFFGroups = commonGroups `intersect` availableFFGroups
        (dhparams, priv, pub) <-
            case possibleFFGroups of
                [] ->
                    let dhparams = fromJust serverDHEParams
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
        case filter (pubKey `signatureCompatible`) commonHashSigs of
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
        let possibleECGroups = commonGroups `intersect` availableECGroups
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

---
-- When the client sends a certificate, check whether
-- it is acceptable for the application.
--
---
makeServerHello
    :: ServerParams
    -> Context
    -> Cipher
    -> Maybe Credential
    -> [ExtensionRaw]
    -> Session
    -> IO Handshake
makeServerHello sparams ctx usedCipher mcred chExts session = do
    resuming <- usingState_ ctx getTLS12SessionResuming
    case mcred of
        Just cred -> storePrivInfoServer ctx cred
        _ -> return () -- return a sensible error
    sniExt <- do
        if resuming
            then return Nothing
            else do
                msni <- usingState_ ctx getClientSNI
                case msni of
                    -- RFC6066: In this event, the server SHALL include
                    -- an extension of type "server_name" in the
                    -- (extended) server hello. The "extension_data"
                    -- field of this extension SHALL be empty.
                    Just _ -> return $ Just $ toExtensionRaw $ ServerName []
                    Nothing -> return Nothing

    let ecPointExt = case extensionLookup EID_EcPointFormats chExts of
            Nothing -> Nothing
            Just _ -> Just $ toExtensionRaw $ EcPointFormatsSupported [EcPointFormat_Uncompressed]

    alpnExt <- applicationProtocol ctx chExts sparams

    ems <- usingHState ctx getExtendedMainSecret
    let emsExt
            | ems = Just $ toExtensionRaw ExtendedMainSecret
            | otherwise = Nothing

    let useTicket = sessionUseTicket $ sharedSessionManager $ serverShared sparams
        sessionTicketExt
            | not resuming && useTicket = Just $ toExtensionRaw $ SessionTicket ""
            | otherwise = Nothing

    -- in TLS12, we need to check as well the certificates we are sending if they have in the extension
    -- the necessary bits set.
    secReneg <- usingState_ ctx getSecureRenegotiation
    secureRenegExt <-
        if secReneg
            then do
                vd <- usingState_ ctx $ do
                    VerifyData cvd <- getVerifyData ClientRole
                    VerifyData svd <- getVerifyData ServerRole
                    return $ SecureRenegotiation cvd svd
                return $ Just $ toExtensionRaw vd
            else return Nothing

    recodeSizeLimitExt <- processRecordSizeLimit ctx chExts False

    srand <-
        serverRandom ctx TLS12 $ supportedVersions $ serverSupported sparams

    let shExts =
            sharedHelloExtensions (serverShared sparams)
                ++ catMaybes
                    [ {- 0x00 -} sniExt
                    , {- 0x0b -} ecPointExt
                    , {- 0x10 -} alpnExt
                    , {- 0x17 -} emsExt
                    , {- 0x1c -} recodeSizeLimitExt
                    , {- 0x23 -} sessionTicketExt
                    , {- 0xff01 -} secureRenegExt
                    ]
    usingState_ ctx $ setVersion TLS12
    usingHState ctx $
        setServerHelloParameters TLS12 srand usedCipher nullCompression
    return $
        ServerHello
            TLS12
            srand
            session
            (CipherId (cipherID usedCipher))
            (compressionID nullCompression)
            shExts

negotiatedGroupsInCommon :: [Group] -> [ExtensionRaw] -> [Group]
negotiatedGroupsInCommon serverGroups chExts =
    lookupAndDecode
        EID_SupportedGroups
        MsgTClientHello
        chExts
        []
        common
  where
    common (SupportedGroups clientGroups) = serverGroups `intersect` clientGroups
