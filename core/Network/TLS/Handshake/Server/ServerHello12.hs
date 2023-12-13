{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.TLS.Handshake.Server.ServerHello12 (
    sendServerHello12,
) where

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

sendServerHello12
    :: ServerParams
    -> Context
    -> (Cipher, Maybe Credential)
    -> CH
    -> IO (Maybe SessionData)
sendServerHello12 sparams ctx (usedCipher, mcred) CH{..} = do
    serverName <- usingState_ ctx getClientSNI
    ems <- processExtendedMasterSec ctx TLS12 MsgTClientHello chExtensions
    resumeSessionData <- case chSession of
        (Session (Just clientSessionId)) -> do
            let resume = sessionResume (sharedSessionManager $ ctxShared ctx) clientSessionId
            resume >>= validateSession chCiphers serverName ems
        (Session Nothing) -> return Nothing
    case resumeSessionData of
        Nothing -> do
            serverSession <- newSession ctx
            usingState_ ctx (setSession serverSession False)
            serverhello <-
                makeServerHello sparams ctx usedCipher mcred chExtensions serverSession
            sendPacket ctx $ Handshake [serverhello]
            sendServerFirstFlight sparams ctx usedCipher mcred chExtensions
            sendPacket ctx (Handshake [ServerHelloDone])
            contextFlush ctx
        Just sessionData -> do
            usingState_ ctx (setSession chSession True)
            serverhello <-
                makeServerHello sparams ctx usedCipher mcred chExtensions chSession
            sendPacket ctx $ Handshake [serverhello]
            let masterSecret = sessionSecret sessionData
            usingHState ctx $ setMasterSecret TLS12 ServerRole masterSecret
            logKey ctx (MasterSecret masterSecret)
            sendChangeCipherAndFinish ctx ServerRole
    return resumeSessionData

validateSession
    :: [CipherID]
    -> Maybe HostName
    -> Bool
    -> Maybe SessionData
    -> IO (Maybe SessionData)
validateSession _ _ _ Nothing = return Nothing
validateSession ciphers sni ems m@(Just sd)
    -- SessionData parameters are assumed to match the local server configuration
    -- so we need to compare only to ClientHello inputs.  Abbreviated handshake
    -- uses the same server_name than full handshake so the same
    -- credentials (and thus ciphers) are available.
    | TLS12 < sessionVersion sd = return Nothing -- fixme
    | sessionCipher sd `notElem` ciphers = return Nothing
    | isJust sni && sessionClientSNI sd /= sni = return Nothing
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
    -> Maybe (CertificateChain, b)
    -> [ExtensionRaw]
    -> IO ()
sendServerFirstFlight sparams ctx usedCipher mcred exts = do
    let certMsg = case mcred of
            Just (srvCerts, _) -> Certificates srvCerts
            _ -> Certificates $ CertificateChain []
    sendPacket ctx $ Handshake [certMsg]

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
  where
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
makeServerHello sparams ctx usedCipher mcred exts session = do
    srand <-
        serverRandom ctx TLS12 $ supportedVersions $ serverSupported sparams
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
    usingState_ ctx $ setVersion TLS12
    usingHState ctx $
        setServerHelloParameters TLS12 srand usedCipher nullCompression
    return $
        ServerHello
            TLS12
            srand
            session
            (cipherID usedCipher)
            (compressionID nullCompression)
            extensions

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
