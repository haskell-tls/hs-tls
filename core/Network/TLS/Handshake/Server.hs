{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Network.TLS.Handshake.Server
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.Server
    ( handshakeServer
    , handshakeServerWith
--    , makeServerHandshake13
    ) where

import Network.TLS.Parameters
import Network.TLS.Imports
import Network.TLS.Context.Internal
import Network.TLS.Session
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Sending13
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Credentials
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Util (bytesEq, catchException, fromJust)
import Network.TLS.IO
import Network.TLS.Types
import Network.TLS.State
import Network.TLS.Handshake.State
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Random
import Network.TLS.Measurement
import qualified Data.ByteString as B
import Data.X509 (ExtKeyUsageFlag(..))

import Control.Monad.State.Strict

import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Certificate
import Network.TLS.X509
import Network.TLS.Handshake.State13
import Network.TLS.Handshake.Common13
import Network.TLS.Packet13 (decodeHandshakes13)

-- Put the server context in handshake mode.
--
-- Expect to receive as first packet a client hello handshake message
--
-- This is just a helper to pop the next message from the recv layer,
-- and call handshakeServerWith.
handshakeServer :: MonadIO m => ServerParams -> Context -> m ()
handshakeServer sparams ctx = liftIO $ do
    hss <- recvPacketHandshake ctx
    case hss of
        [ch] -> handshakeServerWith sparams ctx ch
        _    -> fail ("unexpected handshake received, excepting client hello and received " ++ show hss)

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
--
handshakeServerWith :: ServerParams -> Context -> Handshake -> IO ()
handshakeServerWith sparams ctx clientHello@(ClientHello clientVersion _ clientSession ciphers compressions exts _) = do
    established <- ctxEstablished ctx
    -- renego is not allowed in TLS 1.3
    when (established /= NotEstablished) $ do
        ver <- usingState_ ctx (getVersionWithDefault TLS10)
        when (ver == TLS13) $ throwCore $ Error_Protocol ("renegotiation is not allowed in TLS 1.3", False, NoRenegotiation)
    -- rejecting client initiated renegotiation to prevent DOS.
    unless (supportedClientInitiatedRenegotiation (ctxSupported ctx)) $ do
        eof <- ctxEOF ctx
        when (established == Established && not eof) $
            throwCore $ Error_Protocol ("renegotiation is not allowed", False, NoRenegotiation)
    -- check if policy allow this new handshake to happens
    handshakeAuthorized <- withMeasure ctx (onNewHandshake $ serverHooks sparams)
    unless handshakeAuthorized (throwCore $ Error_HandshakePolicy "server: handshake denied")
    updateMeasure ctx incrementNbHandshakes

    -- Handle Client hello
    processHandshake ctx clientHello

    -- rejecting SSL2. RFC 6176
    when (clientVersion == SSL2) $ throwCore $ Error_Protocol ("SSL 2.0 is not supported", True, ProtocolVersion)
    -- rejecting SSL3. RFC 7568
    -- when (clientVersion == SSL3) $ throwCore $ Error_Protocol ("SSL 3.0 is not supported", True, ProtocolVersion)

    -- Fallback SCSV: RFC7507
    -- TLS_FALLBACK_SCSV: {0x56, 0x00}
    when (supportedFallbackScsv (ctxSupported ctx) &&
          (0x5600 `elem` ciphers) &&
          clientVersion < TLS12) $
        throwCore $ Error_Protocol ("fallback is not allowed", True, InappropriateFallback)

    (chosenVersion, serverName, allCreds)
      <- chooseParameters sparams ctx clientVersion exts

    -- TLS version dependent
    if chosenVersion <= TLS12 then
        handshakeServerWithTLS12 sparams ctx chosenVersion allCreds exts ciphers serverName clientVersion compressions clientSession
      else do
        mapM_ ensureNullCompression compressions
        -- fixme: we should check if the client random is the same as
        -- that in the first client hello in the case of hello retry.
        handshakeServerWithTLS13 sparams ctx chosenVersion allCreds exts ciphers serverName clientSession

handshakeServerWith _ _ _ = throwCore $ Error_Protocol ("unexpected handshake message received in handshakeServerWith", True, HandshakeFailure)


chooseParameters :: ServerParams -> Context -> Version -> [ExtensionRaw]
                 -> IO (Version, Maybe HostName, Credentials)
chooseParameters sparams ctx clientVersion exts = do
    -- choosing TLS version
    let clientVersions = case extensionLookup extensionID_SupportedVersions exts >>= extensionDecode MsgTClientHello of
            Just (SupportedVersionsClientHello vers) -> vers
            _                                        -> []
        serverVersions = supportedVersions $ ctxSupported ctx
        mVersion = debugVersionForced $ serverDebug sparams
    chosenVersion <- case mVersion of
      Just cver -> return cver
      Nothing   ->
        if (TLS13 `elem` serverVersions) && clientVersion == TLS12 && clientVersions /= [] then case findHighestVersionFrom13 clientVersions serverVersions of
                  Nothing -> throwCore $ Error_Protocol ("client versions " ++ show clientVersions ++ " is not supported", True, ProtocolVersion)
                  Just v  -> return v
           else case findHighestVersionFrom clientVersion serverVersions of
                  Nothing -> throwCore $ Error_Protocol ("client version " ++ show clientVersion ++ " is not supported", True, ProtocolVersion)
                  Just v  -> return v

    -- SNI (Server Name Indication)
    let serverName = case extensionLookup extensionID_ServerName exts >>= extensionDecode MsgTClientHello of
            Just (ServerName ns) -> listToMaybe (mapMaybe toHostName ns)
                where toHostName (ServerNameHostName hostName) = Just hostName
                      toHostName (ServerNameOther _)           = Nothing
            _                    -> Nothing
    maybe (return ()) (usingState_ ctx . setClientSNI) serverName

    -- ALPN (Application Layer Protocol Negotiation)
    case extensionLookup extensionID_ApplicationLayerProtocolNegotiation exts >>= extensionDecode MsgTClientHello of
        Just (ApplicationLayerProtocolNegotiation protos) -> usingState_ ctx $ setClientALPNSuggest protos
        _ -> return ()

    extraCreds <- onServerNameIndication (serverHooks sparams) serverName
    let allCreds = extraCreds `mappend` sharedCredentials (ctxShared ctx)

    return (chosenVersion, serverName, allCreds)

-- TLS 1.2 or earlier
handshakeServerWithTLS12 :: ServerParams
                         -> Context
                         -> Version
                         -> Credentials
                         -> [ExtensionRaw]
                         -> [CipherID]
                         -> Maybe String
                         -> Version
                         -> [CompressionID]
                         -> Session
                         -> IO ()
handshakeServerWithTLS12 sparams ctx chosenVersion allCreds exts ciphers serverName clientVersion compressions clientSession = do
    -- If compression is null, commonCompressions should be [0].
    when (null commonCompressions) $ throwCore $
        Error_Protocol ("no compression in common with the client", True, HandshakeFailure)

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

    let possibleGroups   = negotiatedGroupsInCommon ctx exts
        possibleECGroups = possibleGroups `intersect` availableECGroups
        possibleFFGroups = possibleGroups `intersect` availableFFGroups
        hasCommonGroupForECDHE = not (null possibleECGroups)
        hasCommonGroupForFFDHE = not (null possibleFFGroups)
        hasCustomGroupForFFDHE = isJust (serverDHEParams sparams)
        canFFDHE = hasCustomGroupForFFDHE || hasCommonGroupForFFDHE
        hasCommonGroup cipher =
            case cipherKeyExchange cipher of
                CipherKeyExchange_DH_Anon      -> canFFDHE
                CipherKeyExchange_DHE_RSA      -> canFFDHE
                CipherKeyExchange_DHE_DSS      -> canFFDHE
                CipherKeyExchange_ECDHE_RSA    -> hasCommonGroupForECDHE
                CipherKeyExchange_ECDHE_ECDSA  -> hasCommonGroupForECDHE
                _                              -> True -- group not used

        -- Ciphers are selected according to TLS version, availability of
        -- (EC)DHE group and credential depending on key exchange.
        cipherAllowed cipher   = cipherAllowedForVersion chosenVersion cipher && hasCommonGroup cipher
        selectCipher credentials signatureCredentials = filter cipherAllowed (commonCiphers credentials signatureCredentials)

        (creds, signatureCreds, ciphersFilteredVersion)
            = case chosenVersion of
                  TLS12 -> let -- Build a list of all hash/signature algorithms in common between
                               -- client and server.
                               possibleHashSigAlgs = hashAndSignaturesInCommon ctx exts

                               -- Check that a candidate signature credential will be compatible with
                               -- client & server hash/signature algorithms.  This returns Just Int
                               -- in order to sort credentials according to server hash/signature
                               -- preference.  When the certificate has no matching hash/signature in
                               -- 'possibleHashSigAlgs' the result is Nothing, and the credential will
                               -- not be used to sign.  This avoids a failure later in 'decideHashSig'.
                               signingRank cred =
                                   case credentialDigitalSignatureAlg cred of
                                       Just sig -> findIndex (sig `signatureCompatible`) possibleHashSigAlgs
                                       Nothing  -> Nothing

                               -- Finally compute credential lists and resulting cipher list.
                               --
                               -- We try to keep certificates supported by the client, but
                               -- fallback to all credentials if this produces no suitable result
                               -- (see RFC 5246 section 7.4.2 and RFC 8446 section 4.4.2.2).
                               -- The condition is based on resulting (EC)DHE ciphers so that
                               -- filtering credentials does not give advantage to a less secure
                               -- key exchange like CipherKeyExchange_RSA or CipherKeyExchange_DH_Anon.
                               cltCreds    = filterCredentialsWithHashSignatures exts allCreds
                               sigCltCreds = filterSortCredentials signingRank cltCreds
                               sigAllCreds = filterSortCredentials signingRank allCreds
                               cltCiphers  = selectCipher cltCreds sigCltCreds
                               allCiphers  = selectCipher allCreds sigAllCreds

                               resultTuple = if cipherListCredentialFallback cltCiphers
                                                 then (allCreds, sigAllCreds, allCiphers)
                                                 else (cltCreds, sigCltCreds, cltCiphers)
                            in resultTuple
                  _     -> (allCreds, allCreds, selectCipher allCreds allCreds)

    -- The shared cipherlist can become empty after filtering for compatible
    -- creds, check now before calling onCipherChoosing, which does not handle
    -- empty lists.
    when (null ciphersFilteredVersion) $ throwCore $
        Error_Protocol ("no cipher in common with the client", True, HandshakeFailure)

    let usedCipher = onCipherChoosing (serverHooks sparams) chosenVersion ciphersFilteredVersion

    cred <- case cipherKeyExchange usedCipher of
                CipherKeyExchange_RSA       -> return $ credentialsFindForDecrypting creds
                CipherKeyExchange_DH_Anon   -> return   Nothing
                CipherKeyExchange_DHE_RSA   -> return $ credentialsFindForSigning KX_RSA signatureCreds
                CipherKeyExchange_DHE_DSS   -> return $ credentialsFindForSigning KX_DSS signatureCreds
                CipherKeyExchange_ECDHE_RSA -> return $ credentialsFindForSigning KX_RSA signatureCreds
                CipherKeyExchange_ECDHE_ECDSA -> return $ credentialsFindForSigning KX_ECDSA signatureCreds
                _                           -> throwCore $ Error_Protocol ("key exchange algorithm not implemented", True, HandshakeFailure)

    resumeSessionData <- case clientSession of
            (Session (Just clientSessionId)) ->
                let resume = liftIO $ sessionResume (sharedSessionManager $ ctxShared ctx) clientSessionId
                 in validateSession serverName <$> resume
            (Session Nothing)                -> return Nothing

    -- Currently, we don't send back EcPointFormats. In this case,
    -- the client chooses EcPointFormat_Uncompressed.
    case extensionLookup extensionID_EcPointFormats exts >>= extensionDecode MsgTClientHello of
        Just (EcPointFormatsSupported fs) -> usingState_ ctx $ setClientEcPointFormatSuggest fs
        _ -> return ()

    doHandshake sparams cred ctx chosenVersion usedCipher usedCompression clientSession resumeSessionData exts

  where
        commonCiphers creds sigCreds = filter ((`elem` ciphers) . cipherID) (getCiphers sparams creds sigCreds)
        commonCompressions    = compressionIntersectID (supportedCompressions $ ctxSupported ctx) compressions
        usedCompression       = head commonCompressions

        validateSession _   Nothing                         = Nothing
        validateSession sni m@(Just sd)
            -- SessionData parameters are assumed to match the local server configuration
            -- so we need to compare only to ClientHello inputs.  Abbreviated handshake
            -- uses the same server_name than full handshake so the same
            -- credentials (and thus ciphers) are available.
            | clientVersion < sessionVersion sd             = Nothing
            | sessionCipher sd `notElem` ciphers            = Nothing
            | sessionCompression sd `notElem` compressions  = Nothing
            | isJust sni && sessionClientSNI sd /= sni      = Nothing
            | otherwise                                     = m

doHandshake :: ServerParams -> Maybe Credential -> Context -> Version -> Cipher
            -> Compression -> Session -> Maybe SessionData
            -> [ExtensionRaw] -> IO ()
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
            logKey ctx (MasterSecret12 masterSecret)
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
            srand <- serverRandom ctx chosenVersion $ supportedVersions $ serverSupported sparams
            case mcred of
                Just cred          -> storePrivInfoServer ctx cred
                _                  -> return () -- return a sensible error

            -- in TLS12, we need to check as well the certificates we are sending if they have in the extension
            -- the necessary bits set.
            secReneg   <- usingState_ ctx getSecureRenegotiation
            secRengExt <- if secReneg
                    then do
                            vf <- usingState_ ctx $ do
                                    cvf <- getVerifiedData ClientRole
                                    svf <- getVerifiedData ServerRole
                                    return $ extensionEncode (SecureRenegotiation cvf $ Just svf)
                            return [ ExtensionRaw extensionID_SecureRenegotiation vf ]
                    else return []

            protoExt <- applicationProtocol sparams ctx
            sniExt   <- do
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
                      Just _  -> return [ ExtensionRaw extensionID_ServerName ""]
                      Nothing -> return []
            let extensions = secRengExt ++ protoExt ++ sniExt
            usingState_ ctx (setVersion chosenVersion)
            usingHState ctx $ setServerHelloParameters chosenVersion srand usedCipher usedCompression
            return $ ServerHello chosenVersion srand session (cipherID usedCipher)
                                               (compressionID usedCompression) extensions

        handshakeSendServerData = do
            serverSession <- newSession ctx
            usingState_ ctx (setSession serverSession False)
            serverhello   <- makeServerHello serverSession
            -- send ServerHello & Certificate & ServerKeyXchg & CertReq
            let certMsg = case mcred of
                            Just (srvCerts, _) -> Certificates srvCerts
                            _                  -> Certificates $ CertificateChain []
            sendPacket ctx $ Handshake [ serverhello, certMsg ]

            -- send server key exchange if needed
            skx <- case cipherKeyExchange usedCipher of
                        CipherKeyExchange_DH_Anon -> Just <$> generateSKX_DH_Anon
                        CipherKeyExchange_DHE_RSA -> Just <$> generateSKX_DHE KX_RSA
                        CipherKeyExchange_DHE_DSS -> Just <$> generateSKX_DHE KX_DSS
                        CipherKeyExchange_ECDHE_RSA -> Just <$> generateSKX_ECDHE KX_RSA
                        CipherKeyExchange_ECDHE_ECDSA -> Just <$> generateSKX_ECDHE KX_ECDSA
                        _                         -> return Nothing
            maybe (return ()) (sendPacket ctx . Handshake . (:[]) . ServerKeyXchg) skx

            -- FIXME we don't do this on a Anonymous server

            -- When configured, send a certificate request with the DNs of all
            -- configured CA certificates.
            --
            -- Client certificates MUST NOT be accepted if not requested.
            --
            when (serverWantClientCert sparams) $ do
                usedVersion <- usingState_ ctx getVersion
                let defaultCertTypes = [ CertificateType_RSA_Sign
                                       , CertificateType_DSS_Sign
                                       , CertificateType_ECDSA_Sign
                                       ]
                    (certTypes, hashSigs)
                        | usedVersion < TLS12 = (defaultCertTypes, Nothing)
                        | otherwise =
                            let as = supportedHashSignatures $ ctxSupported ctx
                             in (nub $ mapMaybe hashSigToCertType as, Just as)
                    creq = CertRequest certTypes hashSigs
                               (map extractCAname $ serverCACertificates sparams)
                usingHState ctx $ setCertReqSent True
                sendPacket ctx (Handshake [creq])

            -- Send HelloDone
            sendPacket ctx (Handshake [ServerHelloDone])

        extractCAname :: SignedCertificate -> DistinguishedName
        extractCAname cert = certSubjectDN $ getCertificate cert

        setup_DHE = do
            let possibleFFGroups = negotiatedGroupsInCommon ctx exts `intersect` availableFFGroups
            (dhparams, priv, pub) <-
                    case possibleFFGroups of
                        []  ->
                            let dhparams = fromJust "server DHE Params" $ serverDHEParams sparams
                             in case findFiniteFieldGroup dhparams of
                                    Just g  -> do
                                        usingHState ctx $ setNegotiatedGroup g
                                        generateFFDHE ctx g
                                    Nothing -> do
                                        (priv, pub) <- generateDHE ctx dhparams
                                        return (dhparams, priv, pub)
                        g:_ -> do
                            usingHState ctx $ setNegotiatedGroup g
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
        decideHashSig sigAlg = do
            usedVersion <- usingState_ ctx getVersion
            case usedVersion of
              TLS12 -> do
                  let hashSigs = hashAndSignaturesInCommon ctx exts
                  case filter (sigAlg `signatureCompatible`) hashSigs of
                      []  -> error ("no hash signature for " ++ show sigAlg)
                      x:_ -> return $ Just x
              _     -> return Nothing

        generateSKX_DHE kxsAlg = do
            serverParams  <- setup_DHE
            sigAlg <- getLocalDigitalSignatureAlg ctx
            mhashSig <- decideHashSig sigAlg
            signed <- digitallySignDHParams ctx serverParams sigAlg mhashSig
            case kxsAlg of
                KX_RSA -> return $ SKX_DHE_RSA serverParams signed
                KX_DSS -> return $ SKX_DHE_DSS serverParams signed
                _      -> error ("generate skx_dhe unsupported key exchange signature: " ++ show kxsAlg)

        generateSKX_DH_Anon = SKX_DH_Anon <$> setup_DHE

        setup_ECDHE grp = do
            usingHState ctx $ setNegotiatedGroup grp
            (srvpri, srvpub) <- generateECDHE ctx grp
            let serverParams = ServerECDHParams grp srvpub
            usingHState ctx $ setServerECDHParams serverParams
            usingHState ctx $ setGroupPrivate srvpri
            return serverParams

        generateSKX_ECDHE kxsAlg = do
            let possibleECGroups = negotiatedGroupsInCommon ctx exts `intersect` availableECGroups
            grp <- case possibleECGroups of
                     []  -> throwCore $ Error_Protocol ("no common group", True, HandshakeFailure)
                     g:_ -> return g
            serverParams <- setup_ECDHE grp
            sigAlg <- getLocalDigitalSignatureAlg ctx
            mhashSig <- decideHashSig sigAlg
            signed <- digitallySignECDHParams ctx serverParams sigAlg mhashSig
            case kxsAlg of
                KX_RSA   -> return $ SKX_ECDHE_RSA serverParams signed
                KX_ECDSA -> return $ SKX_ECDHE_ECDSA serverParams signed
                _        -> error ("generate skx_ecdhe unsupported key exchange signature: " ++ show kxsAlg)

        -- create a DigitallySigned objects for DHParams or ECDHParams.

-- | receive Client data in handshake until the Finished handshake.
--
--      <- [certificate]
--      <- client key xchg
--      <- [cert verify]
--      <- change cipher
--      <- finish
--
recvClientData :: ServerParams -> Context -> IO ()
recvClientData sparams ctx = runRecvState ctx (RecvStateHandshake processClientCertificate)
  where processClientCertificate (Certificates certs) = do
            clientCertificate sparams ctx certs

            -- FIXME: We should check whether the certificate
            -- matches our request and that we support
            -- verifying with that certificate.

            return $ RecvStateHandshake processClientKeyExchange

        processClientCertificate p = processClientKeyExchange p

        -- cannot use RecvStateHandshake, as the next message could be a ChangeCipher,
        -- so we must process any packet, and in case of handshake call processHandshake manually.
        processClientKeyExchange (ClientKeyXchg _) = return $ RecvStateNext processCertificateVerify
        processClientKeyExchange p                 = unexpected (show p) (Just "client key exchange")

        -- Check whether the client correctly signed the handshake.
        -- If not, ask the application on how to proceed.
        --
        processCertificateVerify (Handshake [hs@(CertVerify dsig)]) = do
            processHandshake ctx hs

            certs <- checkValidClientCertChain ctx "change cipher message expected"

            usedVersion <- usingState_ ctx getVersion
            -- Fetch all handshake messages up to now.
            msgs  <- usingHState ctx $ B.concat <$> getHandshakeMessages

            sigAlgExpected <- getRemoteSignatureAlg

            verif <- checkCertificateVerify ctx usedVersion sigAlgExpected msgs dsig
            clientCertVerify sparams ctx certs verif
            return $ RecvStateNext expectChangeCipher

        processCertificateVerify p = do
            chain <- usingHState ctx getClientCertChain
            case chain of
                Just cc | isNullCertificateChain cc -> return ()
                        | otherwise                 -> throwCore $ Error_Protocol ("cert verify message missing", True, UnexpectedMessage)
                Nothing -> return ()
            expectChangeCipher p

        getRemoteSignatureAlg = do
            pk <- usingHState ctx getRemotePublicKey
            case fromPubKey pk of
              Nothing  -> throwCore $ Error_Protocol ("unsupported remote public key type", True, HandshakeFailure)
              Just sig -> return sig

        expectChangeCipher ChangeCipherSpec = do
            return $ RecvStateHandshake expectFinish

        expectChangeCipher p                = unexpected (show p) (Just "change cipher")

        expectFinish (Finished _) = return RecvStateDone
        expectFinish p            = unexpected (show p) (Just "Handshake Finished")

checkValidClientCertChain :: MonadIO m => Context -> String -> m CertificateChain
checkValidClientCertChain ctx errmsg = do
    chain <- usingHState ctx getClientCertChain
    let throwerror = Error_Protocol (errmsg , True, UnexpectedMessage)
    case chain of
        Nothing -> throwCore throwerror
        Just cc | isNullCertificateChain cc -> throwCore throwerror
                | otherwise                 -> return cc

hashAndSignaturesInCommon :: Context -> [ExtensionRaw] -> [HashAndSignatureAlgorithm]
hashAndSignaturesInCommon ctx exts =
    let cHashSigs = case extensionLookup extensionID_SignatureAlgorithms exts >>= extensionDecode MsgTClientHello of
            -- See Section 7.4.1.4.1 of RFC 5246.
            Nothing -> [(HashSHA1, SignatureECDSA)
                       ,(HashSHA1, SignatureRSA)
                       ,(HashSHA1, SignatureDSS)]
            Just (SignatureAlgorithms sas) -> sas
        sHashSigs = supportedHashSignatures $ ctxSupported ctx
        -- The values in the "signature_algorithms" extension
        -- are in descending order of preference.
        -- However here the algorithms are selected according
        -- to server preference in 'supportedHashSignatures'.
     in sHashSigs `intersect` cHashSigs

negotiatedGroupsInCommon :: Context -> [ExtensionRaw] -> [Group]
negotiatedGroupsInCommon ctx exts = case extensionLookup extensionID_NegotiatedGroups exts >>= extensionDecode MsgTClientHello of
    Just (NegotiatedGroups clientGroups) ->
        let serverGroups = supportedGroups (ctxSupported ctx)
        in serverGroups `intersect` clientGroups
    _                                    -> []

credentialDigitalSignatureAlg :: Credential -> Maybe DigitalSignatureAlg
credentialDigitalSignatureAlg cred =
    findDigitalSignatureAlg (credentialPublicPrivateKeys cred)

filterSortCredentials :: Ord a => (Credential -> Maybe a) -> Credentials -> Credentials
filterSortCredentials rankFun (Credentials creds) =
    let orderedPairs = sortOn fst [ (rankFun cred, cred) | cred <- creds ]
     in Credentials [ cred | (Just _, cred) <- orderedPairs ]

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
filterCredentialsWithHashSignatures :: [ExtensionRaw] -> Credentials -> Credentials
filterCredentialsWithHashSignatures exts =
    case withExt extensionID_SignatureAlgorithmsCert of
        Just (SignatureAlgorithmsCert sas) -> withAlgs sas
        Nothing ->
            case withExt extensionID_SignatureAlgorithms of
                Nothing                        -> id
                Just (SignatureAlgorithms sas) -> withAlgs sas
  where
    withExt extId = extensionLookup extId exts >>= extensionDecode MsgTClientHello
    withAlgs sas = filterCredentials (credentialMatchesHashSignatures sas)
    filterCredentials p (Credentials l) = Credentials (filter p l)

-- returns True if certificate filtering with "signature_algorithms_cert" /
-- "signature_algorithms" produced no ephemeral D-H nor TLS13 cipher (so
-- handshake with lower security)
cipherListCredentialFallback :: [Cipher] -> Bool
cipherListCredentialFallback = all nonDH
  where
    nonDH x = case cipherKeyExchange x of
        CipherKeyExchange_DHE_RSA     -> False
        CipherKeyExchange_DHE_DSS     -> False
        CipherKeyExchange_ECDHE_RSA   -> False
        CipherKeyExchange_ECDHE_ECDSA -> False
        CipherKeyExchange_TLS13       -> False
        _                             -> True

storePrivInfoServer :: MonadIO m => Context -> Credential -> m ()
storePrivInfoServer ctx (cc, privkey) = void (storePrivInfo ctx cc privkey)

data Status13 = Status13 {
    sAuthenticated :: Bool
  , s0RttOK        :: Bool
  , sEstablished   :: Established
  }

-- TLS 1.3 or later
handshakeServerWithTLS13 :: ServerParams
                         -> Context
                         -> Version
                         -> Credentials
                         -> [ExtensionRaw]
                         -> [CipherID]
                         -> Maybe String
                         -> Session
                         -> IO ()
handshakeServerWithTLS13 sparams ctx chosenVersion allCreds exts clientCiphers _serverName clientSession = do
    (choice, keyShares, rtt0)
      <- chooseParameters13 sparams ctx chosenVersion exts clientCiphers
    case findKeyShare keyShares serverGroups of
      Nothing   -> helloRetryRequest sparams ctx choice exts clientSession serverGroups
      Just clientKeyShare -> doHandshake13 sparams ctx choice exts clientSession allCreds clientKeyShare rtt0
  where
    serverGroups = supportedGroups (ctxSupported ctx)

findKeyShare :: [KeyShareEntry] -> [Group] -> Maybe KeyShareEntry
findKeyShare _      [] = Nothing
findKeyShare ks (g:gs) = case find (\ent -> keyShareEntryGroup ent == g) ks of
  Just k  -> Just k
  Nothing -> findKeyShare ks gs

chooseParameters13 :: ServerParams -> Context -> Version
                   -> [ExtensionRaw] -> [CipherID]
                   -> IO (Choice, [KeyShareEntry], Bool)
chooseParameters13 sparams ctx chosenVersion exts clientCiphers = do
    -- Deciding cipher.
    -- The shared cipherlist can become empty after filtering for compatible
    -- creds, check now before calling onCipherChoosing, which does not handle
    -- empty lists.
    when (null ciphersFilteredVersion) $ throwCore $
        Error_Protocol ("no cipher in common with the client", True, HandshakeFailure)
    let usedCipher = onCipherChoosing (serverHooks sparams) chosenVersion ciphersFilteredVersion
        choice = makeChoice chosenVersion usedCipher
        rtt0 = case extensionLookup extensionID_EarlyData exts >>= extensionDecode MsgTClientHello of
                 Just (EarlyDataIndication _) -> True
                 Nothing                      -> False
    when rtt0 $
        -- mark a 0-RTT attempt before a possible HRR, and before updating the
        -- status again if 0-RTT successful
        setEstablished ctx (EarlyDataNotAllowed 3) -- hardcoding
    -- Deciding key exchange from key shares
    keyShares <- case extensionLookup extensionID_KeyShare exts >>= extensionDecode MsgTClientHello of
          Just (KeyShareClientHello kses) -> return kses
          Just _                          -> error "handshakeServerWithTLS13: invalid KeyShare value"
          _                               -> throwCore $ Error_Protocol ("key exchange not implemented, expected key_share extension", True, HandshakeFailure)
    return (choice, keyShares, rtt0)
  where
    ciphersFilteredVersion = filter ((`elem` clientCiphers) . cipherID) serverCiphers
    serverCiphers = filter (cipherAllowedForVersion chosenVersion) (supportedCiphers $ serverSupported sparams)

doHandshake13 :: ServerParams -> Context -> Choice -> [ExtensionRaw] -> Session
              -> Credentials -> KeyShareEntry -> Bool
              -> IO ()
doHandshake13 sparams ctx choice exts clientSession allCreds clientKeyShare rtt0 = do
    (status13, key0, shExts, ecdhe)
      <- checkCondition13 sparams ctx choice exts clientKeyShare rtt0

    key1 <- sendServerHelloAndEncryptedHandshakes sparams ctx choice exts status13 key0 shExts ecdhe clientSession allCreds

    (_key2, expectFinished, expectEndOfEarlyData, sendNST)
      <- establishTLS13 sparams ctx choice exts status13 key1

    if not (sAuthenticated status13) && serverWantClientCert sparams then
        runRecvHandshake13 $ do
          skip <- recvHandshake13 ctx expectCertificate
          unless skip $ recvHandshake13 ctx expectCertVerify
          recvHandshake13 ctx (liftIO . expectFinished)
          liftIO sendNST
      else if s0RttOK status13 then
        setPendingActions ctx [(expectEndOfEarlyData, return ())
                              ,(expectFinished, sendNST)]
      else do
        setPendingActions ctx [(expectFinished, sendNST)]
  where
    expectCertificate :: Handshake13 -> RecvHandshake13M IO Bool
    expectCertificate (Certificate13 certCtx certs _ext) = liftIO $ do
        when (certCtx /= "") $ throwCore $ Error_Protocol ("certificate request context MUST be empty", True, IllegalParameter)
        -- fixme checking _ext
        clientCertificate sparams ctx certs
        return $ isNullCertificateChain certs
    expectCertificate hs = unexpected (show hs) (Just "certificate 13")

    expectCertVerify :: Handshake13 -> RecvHandshake13M IO ()
    expectCertVerify (CertVerify13 sigAlg sig) = liftIO $ do
        hChCc <- transcriptHash ctx
        certs@(CertificateChain cc) <- checkValidClientCertChain ctx "finished 13 message expected"
        pubkey <- case cc of
                    [] -> throwCore $ Error_Protocol ("client certificate missing", True, HandshakeFailure)
                    c:_ -> return $ certPubKey $ getCertificate c
        usingHState ctx $ setPublicKey pubkey
        let keyAlg = fromJust "fromPubKey" (fromPubKey pubkey)
        verif <- checkCertVerify ctx keyAlg sigAlg sig hChCc
        clientCertVerify sparams ctx certs verif
    expectCertVerify hs = unexpected (show hs) (Just "certificate verify 13")

checkCondition13 :: ServerParams -> Context -> Choice -> [ExtensionRaw]
                 -> KeyShareEntry -> Bool
                 -> IO (Status13, SecretTriple, [ExtensionRaw], ByteString)
checkCondition13 sparams ctx choice exts clientKeyShare rtt0 = do
    newSession ctx >>= \ss -> usingState_ ctx (setSession ss False)
    usingHState ctx $ setNegotiatedGroup $ keyShareEntryGroup clientKeyShare
    setServerParameter
    (psk, binderInfo, is0RTTvalid) <- choosePSK
    earlyKey <- calculateEarlySecret ctx choice (Left psk) True
    let earlySecret = triBase earlyKey
    extentions0 <- checkBinder earlySecret binderInfo
    hrr <- usingState_ ctx getTLS13HRR
    let authenticated = isJust binderInfo
        rtt0OK = authenticated && not hrr && rtt0 && rtt0accept && is0RTTvalid
    ----------------------------------------------------------------
    established <- ctxEstablished ctx
    if established /= NotEstablished then
         if rtt0OK then do
             usingHState ctx $ setTLS13HandshakeMode RTT0
             usingHState ctx $ setTLS13RTT0Status RTT0Accepted
           else do
             usingHState ctx $ setTLS13HandshakeMode RTT0
             usingHState ctx $ setTLS13RTT0Status RTT0Rejected
       else
         if authenticated then
             usingHState ctx $ setTLS13HandshakeMode PreSharedKey
           else
             -- FullHandshake or HelloRetryRequest
             return ()
    (ecdhe,keyShare) <- makeServerKeyShare ctx clientKeyShare
    let status13 = Status13 authenticated rtt0OK established
        serverKeyShare = extensionEncode $ KeyShareServerHello keyShare
        selectedVersion = extensionEncode $ SupportedVersionsServerHello chosenVersion
        shExts = ExtensionRaw extensionID_KeyShare serverKeyShare
               : ExtensionRaw extensionID_SupportedVersions selectedVersion
               : extentions0
    return (status13, earlyKey, shExts, ecdhe)
  where
    chosenVersion = cVersion choice
    usedCipher    = cCipher choice
    usedHash      = cHash choice
    setServerParameter = do
        usingState_ ctx $ setVersion chosenVersion
        usingHState ctx $ setHelloParameters13 usedCipher

    choosePSK = case extensionLookup extensionID_PreSharedKey exts >>= extensionDecode MsgTClientHello of
      Just (PreSharedKeyClientHello (PskIdentity sessionId obfAge:_) bnds@(bnd:_)) -> do
          let len = sum (map (\x -> B.length x + 1) bnds) + 2
              mgr = sharedSessionManager $ serverShared sparams
          msdata <- if rtt0 then sessionResumeOnlyOnce mgr sessionId
                            else sessionResume mgr sessionId
          case msdata of
            Just sdata -> do
                let Just tinfo = sessionTicketInfo sdata
                    psk = sessionSecret sdata
                isFresh <- checkFreshness tinfo obfAge
                (isPSKvalid, is0RTTvalid) <- checkSessionEquality sdata
                if isPSKvalid && isFresh then
                    return (psk, Just (bnd,0::Int,len),is0RTTvalid)
                  else
                    -- fall back to full handshake
                    return (zero, Nothing, False)
            _      -> return (zero, Nothing, False)
      _ -> return (zero, Nothing, False)

    checkSessionEquality sdata = do
        msni <- usingState_ ctx getClientSNI
        malpn <- usingState_ ctx getNegotiatedProtocol
        let isSameSNI = sessionClientSNI sdata == msni
            isSameCipher = sessionCipher sdata == cipherID usedCipher
            ciphers = supportedCiphers $ serverSupported sparams
            isSameKDF = case find (\c -> cipherID c == sessionCipher sdata) ciphers of
                Nothing -> False
                Just c  -> cipherHash c == cipherHash usedCipher
            isSameVersion = chosenVersion == sessionVersion sdata
            isSameALPN = sessionALPN sdata == malpn
            isPSKvalid = isSameKDF && isSameSNI -- fixme: SNI is not required
            is0RTTvalid = isSameVersion && isSameCipher && isSameALPN
        return (isPSKvalid, is0RTTvalid)

    rtt0accept = serverEarlyDataSize sparams > 0

    checkBinder _ Nothing = return []
    checkBinder earlySecret (Just (binder,n,tlen)) = do
        binder' <- makePSKBinder ctx earlySecret usedHash tlen Nothing
        unless (binder `bytesEq` binder') $
            decryptError "PSK binder validation failed"
        let selectedIdentity = extensionEncode $ PreSharedKeyServerHello $ fromIntegral n
        return [ExtensionRaw extensionID_PreSharedKey selectedIdentity]

    zero = cZero choice

sendServerHelloAndEncryptedHandshakes ::
       ServerParams -> Context -> Choice -> [ExtensionRaw]
    -> Status13 -> SecretTriple -> [ExtensionRaw]
    -> ByteString -> Session -> Credentials
    -> IO SecretTriple
sendServerHelloAndEncryptedHandshakes sparams ctx choice exts status13 key13 shExts ecdhe clientSession allCreds = runPacketFlight ctx $ do
    helo <- liftIO $ makeServerHello13 sparams ctx choice shExts clientSession
    loadPacket13 ctx $ Handshake13 [helo]
    handKey <- liftIO $ calculateHandshakeSecret ctx choice earlySecret ecdhe
    let ServerHandshakeSecret serverHandshakeSecret = triServer handKey
        ClientHandshakeSecret clientHandshakeSecret = triClient handKey
    liftIO $ do
        setRxState ctx usedHash usedCipher $ if rtt0OK then clientEarlySecret else clientHandshakeSecret
        setTxState ctx usedHash usedCipher serverHandshakeSecret
    loadPacket13 ctx ChangeCipherSpec13
    ext13 <- makeExtensions13 sparams ctx rtt0OK
    loadPacket13 ctx $ Handshake13 [ext13]
    mCredInfo <- decideCredentialInfo ctx status13 exts allCreds
    case mCredInfo of
        Nothing              -> return ()
        Just (cred, hashSig) -> do
            storePrivInfoServer ctx cred
            when (serverWantClientCert sparams) $ do
                let cr = makeCertRequest13 ctx
                loadPacket13 ctx $ Handshake13 [cr]
                usingHState ctx $ setCertReqSent True
            let cert13 = makeCertificate13 cred
            loadPacket13 ctx $ Handshake13 [cert13]
            hChSc <- transcriptHash ctx
            sigAlg <- getLocalDigitalSignatureAlg ctx
            vrfy <- makeCertVerify ctx sigAlg hashSig hChSc
            loadPacket13 ctx $ Handshake13 [vrfy]
    rawFinished <- makeFinished ctx usedHash serverHandshakeSecret
    loadPacket13 ctx $ Handshake13 [rawFinished]
    return handKey
  where
    usedCipher  = cCipher choice
    usedHash    = cHash choice
    rtt0OK      = s0RttOK status13
    earlySecret = triBase key13
    ClientEarlySecret clientEarlySecret = triClient key13

decideCredentialInfo :: MonadIO m => Context -> Status13 -> [ExtensionRaw] -> Credentials -> m (Maybe (Credential, HashAndSignatureAlgorithm))
decideCredentialInfo ctx status13 exts allCreds
  | sAuthenticated status13 = return Nothing
  | otherwise = do
    cHashSigs <- case extensionLookup extensionID_SignatureAlgorithms exts >>= extensionDecode MsgTClientHello of
        Nothing -> throwCore $ Error_Protocol ("no signature_algorithms extension", True, MissingExtension)
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
                Nothing -> throwCore $ Error_Protocol ("credential not found", True, HandshakeFailure)
                mcs -> return mcs
        mcs -> return mcs

establishTLS13 :: ServerParams -> Context -> Choice -> [ExtensionRaw]
               -> Status13 -> SecretTriple
               -> IO (SecretTriple, Handshake13 -> IO (), Handshake13 -> IO (), IO ())
establishTLS13 sparams ctx choice exts status13 key13 = do
    sfSentTime <- getCurrentTimeFromBase
    ----------------------------------------------------------------
    appKey <- calculateTrafficSecret ctx choice handshakeSecret Nothing
    let ClientApplicationSecret0 clientApplicationSecret0 = triClient appKey
        ServerApplicationSecret0 serverApplicationSecret0 = triServer appKey
        applicationSecret = triBase appKey
    setTxState ctx usedHash usedCipher serverApplicationSecret0
    ----------------------------------------------------------------
    if rtt0OK then
        setEstablished ctx (EarlyDataAllowed rtt0max)
      else when (established == NotEstablished) $
        setEstablished ctx (EarlyDataNotAllowed 3) -- hardcoding

    let expectFinished (Finished13 verifyData') = do
            hChBeforeCf <- transcriptHash ctx
            let verifyData = makeVerifyData usedHash clientHandshakeSecret hChBeforeCf
            if verifyData == verifyData' then liftIO $ do
                setEstablished ctx Established
                setRxState ctx usedHash usedCipher clientApplicationSecret0
               else
                decryptError "cannot verify finished"
        expectFinished hs = unexpected (show hs) (Just "finished 13")

    let expectEndOfEarlyData EndOfEarlyData13 =
            setRxState ctx usedHash usedCipher clientHandshakeSecret
        expectEndOfEarlyData hs = unexpected (show hs) (Just "end of early data")
    let sendNST = sendNewSessionTicket sfSentTime applicationSecret
    return (appKey, expectFinished, expectEndOfEarlyData, sendNST)
  where
    usedCipher    = cCipher choice
    usedHash      = cHash choice
    rtt0OK        = s0RttOK status13
    established   = sEstablished status13
    ClientHandshakeSecret clientHandshakeSecret = triClient key13
    handshakeSecret = triBase key13

    rtt0max = safeNonNegative32 $ serverEarlyDataSize sparams

    sendNewSessionTicket sfSentTime applicationSecret = when sendNST $ do
        cfRecvTime <- getCurrentTimeFromBase
        let rtt = cfRecvTime - sfSentTime
        nonce <- getStateRNG ctx 32
        resumptionMasterSecret <- calculateResumptionSecret ctx choice applicationSecret
        let life = 86400 -- 1 day in second: fixme hard coding
            psk = calcPSK choice resumptionMasterSecret nonce
        (label, add) <- generateSession life psk rtt0max rtt
        let nst = createNewSessionTicket life add nonce label rtt0max
        sendPacket13 ctx $ Handshake13 [nst]
      where
        sendNST = (PSK_KE `elem` dhModes) || (PSK_DHE_KE `elem` dhModes)
        dhModes = case extensionLookup extensionID_PskKeyExchangeModes exts >>= extensionDecode MsgTClientHello of
          Just (PskKeyExchangeModes ms) -> ms
          Nothing                       -> []
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
            extensions = [ExtensionRaw extensionID_EarlyData tedi]

makeServerHello13 :: ServerParams -> Context
                  -> Choice -> [ExtensionRaw] -> Session
                  -> IO Handshake13
makeServerHello13 sparams ctx choice shExts clientSession = do
    srand <- serverRandom ctx chosenVersion $ supportedVersions $ serverSupported sparams
    return $ ServerHello13 srand clientSession (cipherID usedCipher) shExts
  where
    chosenVersion = cVersion choice
    usedCipher    = cCipher choice

makeCertRequest13 :: Context -> Handshake13
makeCertRequest13 ctx = CertRequest13 certReqCtx crexts
  where
    certReqCtx = "" -- this must be zero length here.
    sigAlgs = extensionEncode $ SignatureAlgorithms $ supportedHashSignatures $ ctxSupported ctx
    crexts = [ExtensionRaw extensionID_SignatureAlgorithms sigAlgs]

makeCertificate13 :: Credential -> Handshake13
makeCertificate13 (certChain, _) = Certificate13 "" certChain ess
  where
    CertificateChain cs = certChain
    ess = replicate (length cs) []

helloRetryRequest :: MonadIO m => ServerParams -> Context -> Choice -> [ExtensionRaw] -> Session -> [Group] -> m ()
helloRetryRequest sparams ctx choice exts clientSession serverGroups = liftIO $ do
    twice <- usingState_ ctx getTLS13HRR
    when twice $
        throwCore $ Error_Protocol ("Hello retry not allowed again", True, HandshakeFailure)
    usingState_ ctx $ setTLS13HRR True
    usingHState ctx $ setHelloParameters13 $ cCipher choice
    let clientGroups = case extensionLookup extensionID_NegotiatedGroups exts >>= extensionDecode MsgTClientHello of
          Just (NegotiatedGroups gs) -> gs
          Nothing                    -> []
        possibleGroups = serverGroups `intersect` clientGroups
    case possibleGroups of
      [] -> throwCore $ Error_Protocol ("no group in common with the client for HRR", True, HandshakeFailure)
      g:_ -> do
          let serverKeyShare = extensionEncode $ KeyShareHRR g
              selectedVersion = extensionEncode $ SupportedVersionsServerHello $ cVersion choice
              extensions = [ExtensionRaw extensionID_KeyShare serverKeyShare
                           ,ExtensionRaw extensionID_SupportedVersions selectedVersion]
              hrr = ServerHello13 hrrRandom clientSession (cipherID $ cCipher choice) extensions
          usingHState ctx $ setTLS13HandshakeMode HelloRetryRequest
          sendPacket13 ctx $ Handshake13 [hrr]
          handshakeServer sparams ctx

makeExtensions13 :: MonadIO m => ServerParams -> Context -> Bool -> m Handshake13
makeExtensions13 sparams ctx rtt0OK = do
    extensions' <- liftIO $ applicationProtocol sparams ctx
    msni <- liftIO $ usingState_ ctx getClientSNI
    let extensions'' = case msni of
          -- RFC6066: In this event, the server SHALL include
          -- an extension of type "server_name" in the
          -- (extended) server hello. The "extension_data"
          -- field of this extension SHALL be empty.
          Just _  -> ExtensionRaw extensionID_ServerName "" : extensions'
          Nothing -> extensions'
    let extensions
          | rtt0OK = ExtensionRaw extensionID_EarlyData (extensionEncode (EarlyDataIndication Nothing)) : extensions''
          | otherwise = extensions''
    return $ EncryptedExtensions13 extensions

findHighestVersionFrom :: Version -> [Version] -> Maybe Version
findHighestVersionFrom clientVersion allowedVersions =
    case filter (clientVersion >=) $ sortOn Down allowedVersions of
        []  -> Nothing
        v:_ -> Just v

-- We filter our allowed ciphers here according to dynamic credential lists.
-- Credentials 'creds' come from server parameters but also SNI callback.
-- When the key exchange requires a signature, we use a
-- subset of this list named 'sigCreds'.  This list has been filtered in order
-- to remove certificates that are not compatible with hash/signature
-- restrictions (TLS 1.2).
getCiphers :: ServerParams -> Credentials -> Credentials -> [Cipher]
getCiphers sparams creds sigCreds = filter authorizedCKE (supportedCiphers $ serverSupported sparams)
      where authorizedCKE cipher =
                case cipherKeyExchange cipher of
                    CipherKeyExchange_RSA         -> canEncryptRSA
                    CipherKeyExchange_DH_Anon     -> True
                    CipherKeyExchange_DHE_RSA     -> canSignRSA
                    CipherKeyExchange_DHE_DSS     -> canSignDSS
                    CipherKeyExchange_ECDHE_RSA   -> canSignRSA
                    CipherKeyExchange_ECDHE_ECDSA -> canSignECDSA
                    -- unimplemented: non ephemeral DH & ECDH.
                    -- Note, these *should not* be implemented, and have
                    -- (for example) been removed in OpenSSL 1.1.0
                    --
                    CipherKeyExchange_DH_DSS      -> False
                    CipherKeyExchange_DH_RSA      -> False
                    CipherKeyExchange_ECDH_ECDSA  -> False
                    CipherKeyExchange_ECDH_RSA    -> False
                    CipherKeyExchange_TLS13       -> False -- not reached

            canSignDSS    = KX_DSS `elem` signingAlgs
            canSignRSA    = KX_RSA `elem` signingAlgs
            canSignECDSA  = KX_ECDSA `elem` signingAlgs
            canEncryptRSA = isJust $ credentialsFindForDecrypting creds
            signingAlgs   = credentialsListSigningAlgorithms sigCreds

findHighestVersionFrom13 :: [Version] -> [Version] -> Maybe Version
findHighestVersionFrom13 clientVersions serverVersions = case svs `intersect` cvs of
        []  -> Nothing
        v:_ -> Just v
  where
    svs = sortOn Down serverVersions
    cvs = sortOn Down clientVersions

applicationProtocol :: ServerParams -> Context -> IO [ExtensionRaw]
applicationProtocol sparams ctx = do
    suggest <- usingState_ ctx getClientALPNSuggest
    case (onALPNClientSuggest $ serverHooks sparams, suggest) of
        (Just io, Just protos) -> do
            proto <- io protos
            usingState_ ctx $ do
                setExtensionALPN True
                setNegotiatedProtocol proto
            return [ ExtensionRaw extensionID_ApplicationLayerProtocolNegotiation
                                    (extensionEncode $ ApplicationLayerProtocolNegotiation [proto]) ]
        (_, _)                  -> return []

credentialsFindForSigning13 :: [HashAndSignatureAlgorithm] -> Credentials -> Maybe (Credential, HashAndSignatureAlgorithm)
credentialsFindForSigning13 hss0 creds = loop hss0
  where
    loop  []       = Nothing
    loop  (hs:hss) = case credentialsFindForSigning13' hs creds of
        Nothing   -> credentialsFindForSigning13 hss creds
        Just cred -> Just (cred, hs)

-- See credentialsFindForSigning.
credentialsFindForSigning13' :: HashAndSignatureAlgorithm -> Credentials -> Maybe Credential
credentialsFindForSigning13' sigAlg (Credentials l) = find forSigning l
  where
    forSigning cred = case credentialDigitalSignatureAlg cred of
        Nothing  -> False
        Just sig -> sig `signatureCompatible` sigAlg

clientCertificate :: ServerParams -> Context -> CertificateChain -> IO ()
clientCertificate sparams ctx certs = do
    -- run certificate recv hook
    ctxWithHooks ctx (`hookRecvCertificates` certs)
    -- Call application callback to see whether the
    -- certificate chain is acceptable.
    --
    usage <- liftIO $ catchException (onClientCertificate (serverHooks sparams) certs) rejectOnException
    case usage of
        CertificateUsageAccept        -> verifyLeafKeyUsage [KeyUsage_digitalSignature] certs
        CertificateUsageReject reason -> certificateRejected reason

    -- Remember cert chain for later use.
    --
    usingHState ctx $ setClientCertChain certs

clientCertVerify :: ServerParams -> Context -> CertificateChain -> Bool -> IO ()
clientCertVerify sparams ctx certs verif = do
    if verif then do
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
        if res then do
                -- When verification fails, but the
                -- application callbacks accepts, we
                -- also commit the client certificate
                -- chain to the context.
                usingState_ ctx $ setClientCertificateChain certs
                else decryptError "verification failed"

-- | The third argument is client hello.
--   Returning early keys, handshake keys and application keys.
_makeServerHandshake13 :: ServerParams -> Context -> ByteString
                      -> IO ([ByteString], SecretTriple, SecretTriple, SecretTriple, Handshake13 -> IO ())
_makeServerHandshake13 sparams ctx bs = do
    let Right [ClientHello13 clientVersion crand clientSession clientCiphers exts] = decodeHandshakes13 bs
    startHandshake ctx clientVersion crand
    update13 ctx bs
    (chosenVersion, _, allCreds)
      <- chooseParameters sparams ctx clientVersion exts
    (choice, keyShares, rtt0)
      <- chooseParameters13 sparams ctx chosenVersion exts clientCiphers
    let Just clientKeyShare = findKeyShare keyShares serverGroups
    (status13, earlyKey, shExts, ecdhe)
      <- checkCondition13 sparams ctx choice exts clientKeyShare rtt0
    (handKey, handshakes)
      <- makeServerHelloAndEncryptedHandshakes sparams ctx choice exts status13 earlyKey shExts ecdhe clientSession allCreds
    (traffKey, expectFinished, _expectEndOfEarlyData, _sendNST)
      <- establishTLS13 sparams ctx choice exts status13 handKey
    return (handshakes, earlyKey, handKey, traffKey, expectFinished)
  where
    serverGroups = supportedGroups (ctxSupported ctx)

makeServerHelloAndEncryptedHandshakes :: ServerParams -> Context -> Choice -> [ExtensionRaw]
                                      -> Status13 -> SecretTriple -> [ExtensionRaw]
                                      -> ByteString -> Session -> Credentials
                                      -> IO (SecretTriple, [ByteString])
makeServerHelloAndEncryptedHandshakes sparams ctx choice exts status13 key13 shExts ecdhe clientSession allCreds = runPacketFlight2 $ do
    helo <- liftIO $ makeServerHello13 sparams ctx choice shExts clientSession
    appendHandshake13 ctx helo
    handKey <- liftIO $ calculateHandshakeSecret ctx choice earlySecret ecdhe
    let ServerHandshakeSecret serverHandshakeSecret = triServer handKey
        ClientHandshakeSecret clientHandshakeSecret = triClient handKey
    liftIO $ do
        setRxState ctx usedHash usedCipher $ if rtt0OK then clientEarlySecret else clientHandshakeSecret
        setTxState ctx usedHash usedCipher serverHandshakeSecret
    ext13 <- makeExtensions13 sparams ctx rtt0OK
    appendHandshake13 ctx ext13
    mCredInfo <- decideCredentialInfo ctx status13 exts allCreds
    case mCredInfo of
        Nothing              -> return ()
        Just (cred, hashSig) -> do
            storePrivInfoServer ctx cred
            when (serverWantClientCert sparams) $ do
                let cr = makeCertRequest13 ctx
                appendHandshake13 ctx cr
                usingHState ctx $ setCertReqSent True
            let cert13 = makeCertificate13 cred
            appendHandshake13 ctx cert13
            hChSc <- transcriptHash ctx
            sigAlg <- getLocalDigitalSignatureAlg ctx
            vrfy <- makeCertVerify ctx sigAlg hashSig hChSc
            appendHandshake13 ctx vrfy
    rawFinished <- makeFinished ctx usedHash serverHandshakeSecret
    appendHandshake13 ctx rawFinished
    return handKey
  where
    usedCipher = cCipher choice
    usedHash   = cHash choice
    rtt0OK     = s0RttOK status13
    earlySecret = triBase key13
    ClientEarlySecret clientEarlySecret = triClient key13
