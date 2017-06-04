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
    ) where

import Network.TLS.Parameters
import Network.TLS.Imports
import Network.TLS.Context.Internal
import Network.TLS.Session
import Network.TLS.Struct
import Network.TLS.Struct13
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
import Network.TLS.KeySchedule
import Network.TLS.Handshake.Common13

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
        ver <- usingState_ ctx getVersion
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

    extraCreds <- (onServerNameIndication $ serverHooks sparams) serverName
    let allCreds = extraCreds `mappend` sharedCredentials (ctxShared ctx)

    -- TLS version dependent
    if chosenVersion <= TLS12 then
        handshakeServerWithTLS12 sparams ctx chosenVersion allCreds exts ciphers serverName clientVersion compressions clientSession
      else
        -- fixme: we should check if the client random is the same as
        -- that in the first client hello in the case of hello retry.
        handshakeServerWithTLS13 sparams ctx chosenVersion allCreds exts ciphers serverName clientSession
handshakeServerWith _ _ _ = throwCore $ Error_Protocol ("unexpected handshake message received in handshakeServerWith", True, HandshakeFailure)

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

    let usedCipher = (onCipherChoosing $ serverHooks sparams) chosenVersion ciphersFilteredVersion

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
            usingHState ctx $ setMasterSecret chosenVersion ServerRole $ sessionSecret sessionData
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

            protoExt <- applicationProtocol ctx exts sparams
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
            -- FIXME, the acceptable certificate types should be derived from
            -- the supported Signature algorithms, rather than hard-coded here,
            -- when the client certificate is received, the server must check
            -- that the signature matches the advertised parameters.
            --
            -- Client certificates MUST NOT be accepted if not requested.
            --
            when (serverWantClientCert sparams) $ do
                usedVersion <- usingState_ ctx getVersion
                let certTypes = [ CertificateType_RSA_Sign
                                , CertificateType_DSS_Sign ]
                    hashSigs = if usedVersion < TLS12
                                   then Nothing
                                   else Just (supportedHashSignatures $ ctxSupported ctx)
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
            -- run certificate recv hook
            ctxWithHooks ctx (\hooks -> hookRecvCertificates hooks certs)
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

            certs <- checkValidClientCertChain "change cipher message expected"

            usedVersion <- usingState_ ctx getVersion
            -- Fetch all handshake messages up to now.
            msgs  <- usingHState ctx $ B.concat <$> getHandshakeMessages

            sigAlgExpected <- getRemoteSignatureAlg

            verif <- checkCertificateVerify ctx usedVersion sigAlgExpected msgs dsig

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

        checkValidClientCertChain msg = do
            chain <- usingHState ctx getClientCertChain
            let throwerror = Error_Protocol (msg , True, UnexpectedMessage)
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

storePrivInfoServer :: Context -> Credential -> IO ()
storePrivInfoServer ctx (cc, privkey) = void (storePrivInfo ctx cc privkey)

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
    -- Deciding cipher.
    -- The shared cipherlist can become empty after filtering for compatible
    -- creds, check now before calling onCipherChoosing, which does not handle
    -- empty lists.
    when (null ciphersFilteredVersion) $ throwCore $
        Error_Protocol ("no cipher in common with the client", True, HandshakeFailure)
    let usedCipher = (onCipherChoosing $ serverHooks sparams) chosenVersion ciphersFilteredVersion
    -- Deciding key exchange from key shares
    keyShares <- case extensionLookup extensionID_KeyShare exts >>= extensionDecode MsgTClientHello of
          Just (KeyShareClientHello kses) -> return kses
          _                               -> throwCore $ Error_Protocol ("key exchange not implemented", True, HandshakeFailure)
    -- putStrLn $ "keyshare = " ++ show (map keyShareEntryGroup keyShares)
    -- putStrLn "Handshake messages:"
    -- usingHState ctx getHandshakeMessages >>= mapM_ (putStrLn . showBytesHex)
    case findKeyShare keyShares serverGroups of
      Nothing -> helloRetryRequest sparams ctx chosenVersion usedCipher exts serverGroups clientSession
      Just keyShare -> do
        -- When deciding signature algorithm and certificate, we try to keep
        -- certificates supported by the client, but fallback to all credentials
        -- if this produces no suitable result (see RFC 5246 section 7.4.2 and
        -- RFC 8446 section 4.4.2.2).
        let hashSigs = hashAndSignaturesInCommon ctx exts
            cltCreds = filterCredentialsWithHashSignatures exts allCreds
        (cred, hashSig) <- case credentialsFindForSigning13 hashSigs cltCreds of
            Just cs -> return cs
            Nothing ->
                case credentialsFindForSigning13 hashSigs allCreds of
                    Just cs -> return cs
                    Nothing -> throwCore $ Error_Protocol ("credential not found", True, IllegalParameter)
        let usedHash = cipherHash usedCipher
        doHandshake13 sparams cred ctx chosenVersion usedCipher exts usedHash keyShare hashSig clientSession
  where
    ciphersFilteredVersion = filter ((`elem` clientCiphers) . cipherID) serverCiphers
    serverCiphers = filter (cipherAllowedForVersion chosenVersion) (supportedCiphers $ serverSupported sparams)
    serverGroups = supportedGroups (ctxSupported ctx)
    findKeyShare _      [] = Nothing
    findKeyShare ks (g:gs) = case find (\ent -> keyShareEntryGroup ent == g) ks of
      Just k  -> Just k
      Nothing -> findKeyShare ks gs

doHandshake13 :: ServerParams -> Credential -> Context -> Version
              -> Cipher -> [ExtensionRaw]
              -> Hash -> KeyShareEntry -> HashAndSignatureAlgorithm
              -> Session
              -> IO ()
doHandshake13 sparams cred@(certChain, _) ctx chosenVersion usedCipher exts usedHash clientKeyShare hashSig clientSession = do
    newSession ctx >>= \ss -> usingState_ ctx (setSession ss False)
    usingHState ctx $ setNegotiatedGroup $ keyShareEntryGroup clientKeyShare
    srand <- setServerParameter
    (psk, binderInfo, is0RTTvalid) <- choosePSK
    hCh <- transcriptHash ctx
    let earlySecret = hkdfExtract usedHash zero psk
        clientEarlyTrafficSecret = deriveSecret usedHash earlySecret "c e traffic" hCh
    -- dumpKey ctx "CLIENT_EARLY_TRAFFIC_SECRET" clientEarlyTrafficSecret
    -- putStrLn $ "hCh: " ++ showBytesHex hCh
    -- putStrLn $ "earlySecret: " ++ showBytesHex earlySecret
    -- putStrLn $ "clientEarlyTrafficSecret: " ++ showBytesHex clientEarlyTrafficSecret
    extensions <- checkBinder earlySecret binderInfo
    let authenticated = isJust binderInfo
        rtt0OK = authenticated && rtt0 && rtt0accept && is0RTTvalid
    ----------------------------------------------------------------
    if rtt0 then
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
    let handshakeSecret = hkdfExtract usedHash (deriveSecret usedHash earlySecret "derived" (hash usedHash "")) ecdhe
    clientHandshakeTrafficSecret <- runPacketFlight ctx $ do
        sendServerHello keyShare srand extensions
    ----------------------------------------------------------------
        hChSh <- transcriptHash ctx
        let clientHandshakeTrafficSecret = deriveSecret usedHash handshakeSecret "c hs traffic" hChSh
            serverHandshakeTrafficSecret = deriveSecret usedHash handshakeSecret "s hs traffic" hChSh
        -- putStrLn $ "handshakeSecret: " ++ showBytesHex handshakeSecret
        -- putStrLn $ "hChSh: " ++ showBytesHex hChSh
        -- usingHState ctx getHandshakeMessages >>= mapM_ (putStrLn . showBytesHex)
        -- dumpKey ctx "SERVER_HANDSHAKE_TRAFFIC_SECRET" serverHandshakeTrafficSecret
        -- dumpKey ctx "CLIENT_HANDSHAKE_TRAFFIC_SECRET" clientHandshakeTrafficSecret
{-
        if rtt0OK then
           putStrLn "---- setRxState ctx usedHash usedCipher clientEarlyTrafficSecret"
         else
           putStrLn "---- setRxState ctx usedHash usedCipher clientHandshakeTrafficSecret"
-}
        liftIO $ do
            setRxState ctx usedHash usedCipher $ if rtt0OK then clientEarlyTrafficSecret else clientHandshakeTrafficSecret
            setTxState ctx usedHash usedCipher serverHandshakeTrafficSecret
    ----------------------------------------------------------------
        loadPacket13 ctx ChangeCipherSpec13
        sendExtensions rtt0OK
        unless authenticated sendCertAndVerify
        rawFinished <- makeFinished ctx usedHash serverHandshakeTrafficSecret
        loadPacket13 ctx $ Handshake13 [rawFinished]
        return clientHandshakeTrafficSecret
    sfSentTime <- getCurrentTimeFromBase
    ----------------------------------------------------------------
    let masterSecret = hkdfExtract usedHash (deriveSecret usedHash handshakeSecret "derived" (hash usedHash "")) zero
    hChSf <- transcriptHash ctx
    let clientApplicationTrafficSecret0 = deriveSecret usedHash masterSecret "c ap traffic" hChSf
        serverApplicationTrafficSecret0 = deriveSecret usedHash masterSecret "s ap traffic" hChSf
        exporterMasterSecret = deriveSecret usedHash masterSecret "exp master" hChSf
    usingState_ ctx $ setExporterMasterSecret exporterMasterSecret
    ----------------------------------------------------------------
    -- putStrLn $ "hChSf: " ++ showBytesHex hChSf
    -- putStrLn $ "masterSecret: " ++ showBytesHex masterSecret
    -- dumpKey ctx "SERVER_TRAFFIC_SECRET_0" serverApplicationTrafficSecret0
    -- dumpKey ctx "CLIENT_TRAFFIC_SECRET_0" clientApplicationTrafficSecret0
    setTxState ctx usedHash usedCipher serverApplicationTrafficSecret0
    ----------------------------------------------------------------
    let established
         | rtt0OK    = EarlyDataAllowed $ safeNonNegative32 $ serverEarlyDataSize sparams
         | otherwise = EarlyDataNotAllowed
    setEstablished ctx established

    let finishedAction hs@(Finished13 verifyData') = do
            hChBeforeCf <- transcriptHash ctx
            processHandshake13 ctx hs
            let verifyData = makeVerifyData usedHash clientHandshakeTrafficSecret hChBeforeCf
            if verifyData == verifyData' then do
                cfRecvTime <- getCurrentTimeFromBase
                let rtt = cfRecvTime - sfSentTime
                setEstablished ctx Established
                setRxState ctx usedHash usedCipher clientApplicationTrafficSecret0
                sendNewSessionTicket masterSecret rtt
              else
                decryptError "cannot verify finished"
        finishedAction hs = unexpected (show hs) (Just "finished 13")

        endOfEarlyDataAction hs@EndOfEarlyData13 = do
            processHandshake13 ctx hs
            setRxState ctx usedHash usedCipher clientHandshakeTrafficSecret
        endOfEarlyDataAction hs = unexpected (show hs) (Just "end of early data")

    if rtt0OK then do
        setPendingActions ctx [endOfEarlyDataAction, finishedAction]
      else do
        setPendingActions ctx [finishedAction]
  where
    setServerParameter = do
        srand <- serverRandom ctx chosenVersion $ supportedVersions $ serverSupported sparams
        storePrivInfoServer ctx cred
        usingState_ ctx $ setVersion chosenVersion
        usingHState ctx $ setHelloParameters13 usedCipher
        return srand

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

    rtt0accept = safeNonNegative32 (serverEarlyDataSize sparams) > 0
    rtt0 = case extensionLookup extensionID_EarlyData exts >>= extensionDecode MsgTClientHello of
             Just (EarlyDataIndication _) -> True
             Nothing                      -> False

    checkBinder _ Nothing = return []
    checkBinder earlySecret (Just (binder,n,tlen)) = do
        binder' <- makePSKBinder ctx earlySecret usedHash tlen Nothing
        unless (binder `bytesEq` binder') $
            decryptError "PSK binder validation failed"
        let selectedIdentity = extensionEncode $ PreSharedKeyServerHello $ fromIntegral n
        return [ExtensionRaw extensionID_PreSharedKey selectedIdentity]

    sendServerHello keyShare srand extensions = do
        let serverKeyShare = extensionEncode $ KeyShareServerHello keyShare
            selectedVersion = extensionEncode $ SupportedVersionsServerHello chosenVersion
            extensions' = ExtensionRaw extensionID_KeyShare serverKeyShare
                        : ExtensionRaw extensionID_SupportedVersions selectedVersion
                        : extensions
            helo = ServerHello13 srand clientSession (cipherID usedCipher) extensions'
        loadPacket13 ctx $ Handshake13 [helo]

    sendCertAndVerify = do
        let CertificateChain cs = certChain
            ess = replicate (length cs) []
        loadPacket13 ctx $ Handshake13 [Certificate13 "" certChain ess]
        hChSc <- transcriptHash ctx
        sigAlg <- getLocalDigitalSignatureAlg ctx
        vrfy <- makeServerCertVerify ctx sigAlg hashSig hChSc
        loadPacket13 ctx $ Handshake13 [vrfy]

    sendExtensions rtt0OK = do
        extensions' <- liftIO $ applicationProtocol ctx exts sparams
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
        loadPacket13 ctx $ Handshake13 [EncryptedExtensions13 extensions]

    sendNewSessionTicket masterSecret rtt = when sendNST $ do
        hChCf <- transcriptHash ctx
        nonce <- usingState_ ctx $ genRandom 32
        let resumptionMasterSecret = deriveSecret usedHash masterSecret "res master" hChCf
            life = 86400 -- 1 day in second: fixme hard coding
            psk = hkdfExpandLabel usedHash resumptionMasterSecret "resumption" nonce hashSize
            maxSize = safeNonNegative32 $ serverEarlyDataSize sparams
        (label, add) <- generateSession life psk maxSize
        let nst = createNewSessionTicket life add nonce label maxSize
        sendPacket13 ctx $ Handshake13 [nst]
      where
        sendNST = (PSK_KE `elem` dhModes) || (PSK_DHE_KE `elem` dhModes)
        dhModes = case extensionLookup extensionID_PskKeyExchangeModes exts >>= extensionDecode MsgTClientHello of
          Just (PskKeyExchangeModes ms) -> ms
          Nothing                       -> []
        generateSession life psk maxSize = do
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

    hashSize = hashDigestSize usedHash
    zero = B.replicate hashSize 0

helloRetryRequest :: MonadIO m => ServerParams -> Context -> Version -> Cipher -> [ExtensionRaw] -> [Group] -> Session -> m ()
helloRetryRequest sparams ctx chosenVersion usedCipher exts serverGroups clientSession = liftIO $ do
    twice <- usingState_ ctx getTLS13HRR
    when twice $
        throwCore $ Error_Protocol ("Hello retry not allowed again", True, HandshakeFailure)
    usingState_ ctx $ setTLS13HRR True
    usingHState ctx $ setHelloParameters13 usedCipher
    let clientGroups = case extensionLookup extensionID_NegotiatedGroups exts >>= extensionDecode MsgTClientHello of
          Just (NegotiatedGroups gs) -> gs
          Nothing                    -> []
        possibleGroups = serverGroups `intersect` clientGroups
    case possibleGroups of
      [] -> throwCore $ Error_Protocol ("key exchange not implemented in HRR", True, HandshakeFailure)
      g:_ -> do
          let serverKeyShare = extensionEncode $ KeyShareHRR g
              selectedVersion = extensionEncode $ SupportedVersionsServerHello chosenVersion
              extensions = [ExtensionRaw extensionID_KeyShare serverKeyShare
                           ,ExtensionRaw extensionID_SupportedVersions selectedVersion]
              hrr = ServerHello13 hrrRandom clientSession (cipherID usedCipher) extensions
          usingHState ctx $ setTLS13HandshakeMode HelloRetryRequest
          sendPacket13 ctx $ Handshake13 [hrr]
          handshakeServer sparams ctx

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

applicationProtocol :: Context -> [ExtensionRaw] -> ServerParams -> IO [ExtensionRaw]
applicationProtocol ctx exts sparams
    | clientALPNSuggest = do
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
    | otherwise = return []
  where
    clientALPNSuggest = isJust $ extensionLookup extensionID_ApplicationLayerProtocolNegotiation exts

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
