{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Network.TLS.Handshake.Client
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.Client
    ( handshakeClient
    , handshakeClientWith
    ) where

import Network.TLS.Crypto
import Network.TLS.Context.Internal
import Network.TLS.Parameters
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Packet hiding (getExtensions)
import Network.TLS.Packet13
import Network.TLS.ErrT
import Network.TLS.Extension
import Network.TLS.IO
import Network.TLS.Sending13
import Network.TLS.Imports
import Network.TLS.State
import Network.TLS.Measurement
import Network.TLS.Util (bytesEq, catchException, fromJust)
import Network.TLS.Types
import Network.TLS.X509
import qualified Data.ByteString as B
import Data.X509 (ExtKeyUsageFlag(..))

import Control.Monad.State.Strict
import Control.Exception (SomeException)

import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.Certificate
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Random
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.KeySchedule
import Network.TLS.Wire

handshakeClientWith :: ClientParams -> Context -> Handshake -> IO ()
handshakeClientWith cparams ctx HelloRequest = handshakeClient cparams ctx
handshakeClientWith _       _   _            = throwCore $ Error_Protocol ("unexpected handshake message received in handshakeClientWith", True, HandshakeFailure)

-- client part of handshake. send a bunch of handshake of client
-- values intertwined with response from the server.
handshakeClient :: ClientParams -> Context -> IO ()
handshakeClient cparams ctx = do
    let groups = case clientWantSessionResume cparams of
              Nothing         -> supportedGroups (ctxSupported ctx)
              Just (_, sdata) -> case sessionGroup sdata of
                  Nothing  -> [] -- TLS 1.2 or earlier
                  Just grp -> [grp]
    handshakeClient' cparams ctx groups Nothing

handshakeClient' :: ClientParams -> Context -> [Group] -> Maybe ClientRandom -> IO ()
handshakeClient' cparams ctx groups mcrand = do
    -- putStr $ "groups = " ++ show groups ++ ", keyshare = ["
    -- case groups of
    --     []  -> putStrLn "]"
    --     g:_ -> putStrLn $ show g ++ "]"
    updateMeasure ctx incrementNbHandshakes
    sentExtensions <- sendClientHello mcrand
    recvServerHello sentExtensions
    ver <- usingState_ ctx getVersion
    -- recvServerHello sets TLS13HRR according to the server random.
    -- For 1st server hello, getTLS13HR returns True if it is HRR and False otherwise.
    -- For 2nd server hello, getTLS13HR returns False since it is NOT HRR.
    hrr <- usingState_ ctx getTLS13HRR
    if ver == TLS13 then do
        if hrr then case drop 1 groups of
            []      -> throwCore $ Error_Protocol ("group is exhausted in the client side", True, IllegalParameter)
            groups' -> do
                mks <- usingState_ ctx getTLS13KeyShare
                case mks of
                  Just (KeyShareHRR selectedGroup)
                    | selectedGroup `elem` groups' -> do
                          usingHState ctx $ setTLS13HandshakeMode HelloRetryRequest
                          crand <- usingHState ctx $ hstClientRandom <$> get
                          handshakeClient' cparams ctx [selectedGroup] (Just crand)
                  _                    -> throwCore $ Error_Protocol ("server-selected group is not supported", True, IllegalParameter)
          else do
            handshakeClient13 cparams ctx
      else do
        sessionResuming <- usingState_ ctx isSessionResuming
        if sessionResuming
            then sendChangeCipherAndFinish ctx ClientRole
            else do sendClientData cparams ctx
                    sendChangeCipherAndFinish ctx ClientRole
                    recvChangeCipherAndFinish ctx
        handshakeTerminate ctx
  where ciphers      = supportedCiphers $ ctxSupported ctx
        compressions = supportedCompressions $ ctxSupported ctx
        highestVer = maximum $ supportedVersions $ ctxSupported ctx
        tls13 = highestVer >= TLS13
        getExtensions = sequence [sniExtension
                                 ,secureReneg
                                 ,alpnExtension
                                 ,groupExtension
                                 ,ecPointExtension
                                 --,sessionTicketExtension
                                 ,signatureAlgExtension
                                 -- ,heartbeatExtension
                                 ,versionExtension
                                 ,earlyDataExtension
                                 ,keyshareExtension
                                 ,pskExchangeModeExtension
                                 ,preSharedKeyExtension
                                 ,cookieExtension
                                 ]

        toExtensionRaw :: Extension e => e -> ExtensionRaw
        toExtensionRaw ext = ExtensionRaw (extensionID ext) (extensionEncode ext)

        secureReneg  =
                if supportedSecureRenegotiation $ ctxSupported ctx
                then usingState_ ctx (getVerifiedData ClientRole) >>= \vd -> return $ Just $ toExtensionRaw $ SecureRenegotiation vd Nothing
                else return Nothing
        alpnExtension = do
            mprotos <- onSuggestALPN $ clientHooks cparams
            case mprotos of
                Nothing -> return Nothing
                Just protos -> do
                    usingState_ ctx $ setClientALPNSuggest protos
                    return $ Just $ toExtensionRaw $ ApplicationLayerProtocolNegotiation protos
        sniExtension = if clientUseServerNameIndication cparams
                         then do let sni = fst $ clientServerIdentification cparams
                                 usingState_ ctx $ setClientSNI sni
                                 return $ Just $ toExtensionRaw $ ServerName [ServerNameHostName sni]
                         else return Nothing

        groupExtension = return $ Just $ toExtensionRaw $ NegotiatedGroups (supportedGroups $ ctxSupported ctx)
        ecPointExtension = return $ Just $ toExtensionRaw $ EcPointFormatsSupported [EcPointFormat_Uncompressed]
                                --[EcPointFormat_Uncompressed,EcPointFormat_AnsiX962_compressed_prime,EcPointFormat_AnsiX962_compressed_char2]
        --heartbeatExtension = return $ Just $ toExtensionRaw $ HeartBeat $ HeartBeat_PeerAllowedToSend
        --sessionTicketExtension = return $ Just $ toExtensionRaw $ SessionTicket

        signatureAlgExtension = return $ Just $ toExtensionRaw $ SignatureAlgorithms $ supportedHashSignatures $ clientSupported cparams

        versionExtension
          | tls13 = do
                let vers = filter (>= TLS12) $ supportedVersions $ ctxSupported ctx
                return $ Just $ toExtensionRaw $ SupportedVersionsClientHello vers
          | otherwise = return Nothing

        -- FIXME
        keyshareExtension
          | tls13 = case groups of
                  []    -> return Nothing
                  grp:_ -> do
                      (cpri, ent) <- makeClientKeyShare ctx grp
                      usingHState ctx $ setGroupPrivate cpri
                      return $ Just $ toExtensionRaw $ KeyShareClientHello [ent]
          | otherwise = return Nothing

        sessionAndCipherToResume13 = do
            guard tls13
            (sid, sdata) <- clientWantSessionResume cparams
            guard (sessionVersion sdata >= TLS13)
            sCipher <- find (\c -> cipherID c == sessionCipher sdata) ciphers
            return (sid, sdata, sCipher)

        preSharedKeyExtension =
            case sessionAndCipherToResume13 of
                Nothing -> return Nothing
                Just (sid, sdata, sCipher) -> do
                      let usedHash = cipherHash sCipher
                          siz = hashDigestSize usedHash
                          zero = B.replicate siz 0
                          tinfo = fromJust "sessionTicketInfo" $ sessionTicketInfo sdata
                      age <- getAge tinfo
                      if isAgeValid age tinfo then do
                          let obfAge = ageToObfuscatedAge age tinfo
                          let identity = PskIdentity sid obfAge
                              offeredPsks = PreSharedKeyClientHello [identity] [zero]
                          return $ Just $ toExtensionRaw offeredPsks
                        else
                          return Nothing

        pskExchangeModeExtension
          | tls13     = return $ Just $ toExtensionRaw $ PskKeyExchangeModes [PSK_DHE_KE]
          | otherwise = return Nothing

        earlyDataExtension = case check0RTT of
            Nothing -> return $ Nothing
            _       -> return $ Just $ toExtensionRaw (EarlyDataIndication Nothing)

        cookieExtension = do
            mcookie <- usingState_ ctx getTLS13Cookie
            case mcookie of
              Nothing     -> return Nothing
              Just cookie -> return $ Just $ toExtensionRaw cookie

        clientSession = case clientWantSessionResume cparams of
            Nothing -> Session Nothing
            Just (sid, sdata)
              | sessionVersion sdata >= TLS13 -> Session Nothing
              | otherwise                     -> Session (Just sid)

        adjustExtentions exts ch =
            case sessionAndCipherToResume13 of
                Nothing -> return exts
                Just (_, sdata, sCipher) -> do
                      let usedHash = cipherHash sCipher
                          siz = hashDigestSize usedHash
                          zero = B.replicate siz 0
                          psk = sessionSecret sdata
                          earlySecret = hkdfExtract usedHash zero psk
                      usingHState ctx $ setTLS13Secret (EarlySecret earlySecret)
                      let ech = encodeHandshake ch
                      binder <- makePSKBinder ctx earlySecret usedHash (siz + 3) (Just ech)
                      let exts' = init exts ++ [adjust (last exts)]
                          adjust (ExtensionRaw eid withoutBinders) = ExtensionRaw eid withBinders
                            where
                              withBinders = replacePSKBinder withoutBinders binder
                      return exts'

        sendClientHello mcr = do
            crand <- case mcr of
              Nothing -> clientRandom ctx
              Just cr -> return cr
            let ver = if tls13 then TLS12 else highestVer
            hrr <- usingState_ ctx getTLS13HRR
            unless hrr $ startHandshake ctx ver crand
            usingState_ ctx $ setVersionIfUnset highestVer
            let cipherIds = map cipherID ciphers
                compIds = map compressionID compressions
                mkClientHello exts = ClientHello ver crand clientSession cipherIds compIds exts Nothing
            extensions0 <- catMaybes <$> getExtensions
            extensions <- adjustExtentions extensions0 $ mkClientHello extensions0
            sendPacket ctx $ Handshake [mkClientHello extensions]
            send0RTT
            return $ map (\(ExtensionRaw i _) -> i) extensions

        check0RTT = do
            (_, sdata, sCipher) <- sessionAndCipherToResume13
            earlyData <- clientEarlyData cparams
            guard (fromIntegral (B.length earlyData) <= sessionMaxEarlyDataSize sdata)
            return (sCipher, earlyData)

        send0RTT = case check0RTT of
            Nothing -> return ()
            Just (usedCipher, earlyData) -> do
                let usedHash = cipherHash usedCipher
                -- fixme: not initialized yet
                -- hCh <- transcriptHash ctx
                hmsgs <- usingHState ctx getHandshakeMessages
                let hCh = hash usedHash $ B.concat hmsgs -- fixme
                EarlySecret earlySecret <- usingHState ctx getTLS13Secret -- fixme
                let clientEarlyTrafficSecret = deriveSecret usedHash earlySecret "c e traffic" hCh
                -- putStrLn $ "hCh: " ++ showBytesHex hCh
                -- dumpKey ctx "CLIENT_EARLY_TRAFFIC_SECRET" clientEarlyTrafficSecret
                -- putStrLn "---- setTxState ctx usedHash usedCipher clientEarlyTrafficSecret"
                setTxState ctx usedHash usedCipher clientEarlyTrafficSecret
                -- fixme
                Right eEarlyData <- writePacket13 ctx $ AppData13 earlyData
                sendBytes13 ctx eEarlyData
                usingHState ctx $ setTLS13RTT0Status RTT0Sent

        recvServerHello sentExts = runRecvState ctx recvState
          where recvState = RecvStateNext $ \p ->
                    case p of
                        Handshake hs -> onRecvStateHandshake ctx (RecvStateHandshake $ onServerHello ctx cparams sentExts) hs -- this adds SH to hstHandshakeMessages
                        Alert a      ->
                            case a of
                                [(AlertLevel_Warning, UnrecognizedName)] ->
                                    if clientUseServerNameIndication cparams
                                        then return recvState
                                        else throwAlert a
                                _ -> throwAlert a
                        _ -> fail ("unexepected type received. expecting handshake and got: " ++ show p)
                throwAlert a = usingState_ ctx $ throwError $ Error_Protocol ("expecting server hello, got alert : " ++ show a, True, HandshakeFailure)

-- | send client Data after receiving all server data (hello/certificates/key).
--
--       -> [certificate]
--       -> client key exchange
--       -> [cert verify]
sendClientData :: ClientParams -> Context -> IO ()
sendClientData cparams ctx = sendCertificate >> sendClientKeyXchg >> sendCertificateVerify
  where
        -- When the server requests a client certificate, we
        -- fetch a certificate chain from the callback in the
        -- client parameters and send it to the server.
        -- Additionally, we store the private key associated
        -- with the first certificate in the chain for later
        -- use.
        --
        sendCertificate = do
            certRequested <- usingHState ctx getClientCertRequest
            case certRequested of
                Nothing ->
                    return ()

                Just req -> do
                    certChain <- liftIO $ (onCertificateRequest $ clientHooks cparams) req `catchException`
                                 throwMiscErrorOnException "certificate request callback failed"

                    usingHState ctx $ setClientCertSent False
                    case certChain of
                        Nothing                       -> sendPacket ctx $ Handshake [Certificates (CertificateChain [])]
                        Just (CertificateChain [], _) -> sendPacket ctx $ Handshake [Certificates (CertificateChain [])]
                        Just (cc@(CertificateChain (c:_)), pk) -> do
                            case certPubKey $ getCertificate c of
                                PubKeyRSA _ -> return ()
                                PubKeyDSA _ -> return ()
                                _           -> throwCore $ Error_Protocol ("no supported certificate type", True, HandshakeFailure)
                            usingHState ctx $ setPrivateKey pk
                            usingHState ctx $ setClientCertSent True
                            sendPacket ctx $ Handshake [Certificates cc]

        sendClientKeyXchg = do
            cipher <- usingHState ctx getPendingCipher
            ckx <- case cipherKeyExchange cipher of
                CipherKeyExchange_RSA -> do
                    clientVersion <- usingHState ctx $ gets hstClientVersion
                    (xver, prerand) <- usingState_ ctx $ (,) <$> getVersion <*> genRandom 46

                    let premaster = encodePreMasterSecret clientVersion prerand
                    usingHState ctx $ setMasterSecretFromPre xver ClientRole premaster
                    encryptedPreMaster <- do
                        -- SSL3 implementation generally forget this length field since it's redundant,
                        -- however TLS10 make it clear that the length field need to be present.
                        e <- encryptRSA ctx premaster
                        let extra = if xver < TLS10
                                        then B.empty
                                        else encodeWord16 $ fromIntegral $ B.length e
                        return $ extra `B.append` e
                    return $ CKX_RSA encryptedPreMaster
                CipherKeyExchange_DHE_RSA -> getCKX_DHE
                CipherKeyExchange_DHE_DSS -> getCKX_DHE
                CipherKeyExchange_ECDHE_RSA -> getCKX_ECDHE
                CipherKeyExchange_ECDHE_ECDSA -> getCKX_ECDHE
                _ -> throwCore $ Error_Protocol ("client key exchange unsupported type", True, HandshakeFailure)
            sendPacket ctx $ Handshake [ClientKeyXchg ckx]
          where getCKX_DHE = do
                    xver <- usingState_ ctx getVersion
                    serverParams <- usingHState ctx getServerDHParams

                    let params  = serverDHParamsToParams serverParams
                        ffGroup = findFiniteFieldGroup params
                        srvpub  = serverDHParamsToPublic serverParams

                    (clientDHPub, premaster) <-
                        case ffGroup of
                             Nothing  -> do
                                 groupUsage <- (onCustomFFDHEGroup $ clientHooks cparams) params srvpub `catchException`
                                                   throwMiscErrorOnException "custom group callback failed"
                                 case groupUsage of
                                     GroupUsageInsecure           -> throwCore $ Error_Protocol ("FFDHE group is not secure enough", True, InsufficientSecurity)
                                     GroupUsageUnsupported reason -> throwCore $ Error_Protocol ("unsupported FFDHE group: " ++ reason, True, HandshakeFailure)
                                     GroupUsageInvalidPublic      -> throwCore $ Error_Protocol ("invalid server public key", True, HandshakeFailure)
                                     GroupUsageValid              -> do
                                         (clientDHPriv, clientDHPub) <- generateDHE ctx params
                                         let premaster = dhGetShared params clientDHPriv srvpub
                                         return (clientDHPub, premaster)
                             Just grp -> do
                                 usingHState ctx $ setNegotiatedGroup grp
                                 dhePair <- generateFFDHEShared ctx grp srvpub
                                 case dhePair of
                                     Nothing   -> throwCore $ Error_Protocol ("invalid server public key", True, HandshakeFailure)
                                     Just pair -> return pair

                    usingHState ctx $ setMasterSecretFromPre xver ClientRole premaster

                    return $ CKX_DH clientDHPub

                getCKX_ECDHE = do
                    ServerECDHParams grp srvpub <- usingHState ctx getServerECDHParams
                    usingHState ctx $ setNegotiatedGroup grp
                    ecdhePair <- generateECDHEShared ctx srvpub
                    case ecdhePair of
                        Nothing                  -> throwCore $ Error_Protocol ("invalid server public key", True, HandshakeFailure)
                        Just (clipub, premaster) -> do
                            xver <- usingState_ ctx getVersion
                            usingHState ctx $ setMasterSecretFromPre xver ClientRole premaster
                            return $ CKX_ECDH $ encodeGroupPublic clipub

        -- In order to send a proper certificate verify message,
        -- we have to do the following:
        --
        -- 1. Determine which signing algorithm(s) the server supports
        --    (we currently only support RSA).
        -- 2. Get the current handshake hash from the handshake state.
        -- 3. Sign the handshake hash
        -- 4. Send it to the server.
        --
        sendCertificateVerify = do
            usedVersion <- usingState_ ctx getVersion

            -- Only send a certificate verify message when we
            -- have sent a non-empty list of certificates.
            --
            certSent <- usingHState ctx getClientCertSent
            when certSent $ do
                sigAlg <- getLocalSignatureAlg

                mhashSig <- case usedVersion of
                    TLS12 -> do
                        Just (_, Just hashSigs, _) <- usingHState ctx getClientCertRequest
                        -- The values in the "signature_algorithms" extension
                        -- are in descending order of preference.
                        -- However here the algorithms are selected according
                        -- to client preference in 'supportedHashSignatures'.
                        let suppHashSigs = supportedHashSignatures $ ctxSupported ctx
                            matchHashSigs = filter (sigAlg `signatureCompatible`) suppHashSigs
                            hashSigs' = filter (`elem` hashSigs) matchHashSigs

                        when (null hashSigs') $
                            throwCore $ Error_Protocol ("no " ++ show sigAlg ++ " hash algorithm in common with the server", True, HandshakeFailure)
                        return $ Just $ head hashSigs'
                    _     -> return Nothing

                -- Fetch all handshake messages up to now.
                msgs   <- usingHState ctx $ B.concat <$> getHandshakeMessages
                sigDig <- createCertificateVerify ctx usedVersion sigAlg mhashSig msgs
                sendPacket ctx $ Handshake [CertVerify sigDig]

        getLocalSignatureAlg = do
            pk <- usingHState ctx getLocalPrivateKey
            case pk of
                PrivKeyRSA _   -> return RSA
                PrivKeyDSA _   -> return DSS

processServerExtension :: ExtensionRaw -> TLSSt ()
processServerExtension (ExtensionRaw extID content)
  | extID == extensionID_SecureRenegotiation = do
        cv <- getVerifiedData ClientRole
        sv <- getVerifiedData ServerRole
        let bs = extensionEncode (SecureRenegotiation cv $ Just sv)
        unless (bs `bytesEq` content) $ throwError $ Error_Protocol ("server secure renegotiation data not matching", True, HandshakeFailure)
        return ()
  | extID == extensionID_SupportedVersions = case extensionDecode MsgTServerHello content of
      Just (SupportedVersionsServerHello ver) -> setVersion ver
      _                                       -> return ()
  | extID == extensionID_KeyShare = do
        hrr <- getTLS13HRR
        let msgt = if hrr then MsgTHelloRetryRequest else MsgTServerHello
        setTLS13KeyShare $ extensionDecode msgt content
  | extID == extensionID_PreSharedKey =
        setTLS13PreSharedKey $ extensionDecode MsgTServerHello content
processServerExtension _ = return ()

throwMiscErrorOnException :: String -> SomeException -> IO a
throwMiscErrorOnException msg e =
    throwCore $ Error_Misc $ msg ++ ": " ++ show e

-- | onServerHello process the ServerHello message on the client.
--
-- 1) check the version chosen by the server is one allowed by parameters.
-- 2) check that our compression and cipher algorithms are part of the list we sent
-- 3) check extensions received are part of the one we sent
-- 4) process the session parameter to see if the server want to start a new session or can resume
-- 5) if no resume switch to processCertificate SM or in resume switch to expectChangeCipher
--
onServerHello :: Context -> ClientParams -> [ExtensionID] -> Handshake -> IO (RecvState IO)
onServerHello ctx cparams sentExts (ServerHello rver serverRan serverSession cipher compression exts) = do
    when (rver == SSL2) $ throwCore $ Error_Protocol ("ssl2 is not supported", True, ProtocolVersion)
    -- find the compression and cipher methods that the server want to use.
    cipherAlg <- case find ((==) cipher . cipherID) (supportedCiphers $ ctxSupported ctx) of
                     Nothing  -> throwCore $ Error_Protocol ("server choose unknown cipher", True, HandshakeFailure)
                     Just alg -> return alg
    compressAlg <- case find ((==) compression . compressionID) (supportedCompressions $ ctxSupported ctx) of
                       Nothing  -> throwCore $ Error_Protocol ("server choose unknown compression", True, HandshakeFailure)
                       Just alg -> return alg

    -- intersect sent extensions in client and the received extensions from server.
    -- if server returns extensions that we didn't request, fail.
    let checkExt (ExtensionRaw i _)
          | i == extensionID_Cookie = False -- for HRR
          | otherwise               = i `notElem` sentExts
    unless (null $ filter checkExt exts) $
        throwCore $ Error_Protocol ("spurious extensions received", True, UnsupportedExtension)

    let resumingSession =
            case clientWantSessionResume cparams of
                Just (sessionId, sessionData) -> if serverSession == Session (Just sessionId) then Just sessionData else Nothing
                Nothing                       -> Nothing
        isHRR = serverRan == hrrRandom
    usingState_ ctx $ do
        setTLS13HRR isHRR
        case extensionLookup extensionID_Cookie exts >>= extensionDecode MsgTServerHello of
          Just cookie -> setTLS13Cookie cookie
          _           -> return ()
        setSession serverSession (isJust resumingSession)
        setVersion rver -- must be before processing supportedVersions ext
        mapM_ processServerExtension exts

    setALPN ctx exts

    ver <- usingState_ ctx getVersion
    case find (== ver) (supportedVersions $ ctxSupported ctx) of
        Nothing -> throwCore $ Error_Protocol ("server version " ++ show ver ++ " is not supported", True, ProtocolVersion)
        Just _  -> return ()
    if ver == TLS13 then do
        usingHState ctx $ setHelloParameters13 cipherAlg isHRR
        return RecvStateDone
      else do
        usingHState ctx $ setServerHelloParameters rver serverRan cipherAlg compressAlg
        case resumingSession of
            Nothing          -> return $ RecvStateHandshake (processCertificate cparams ctx)
            Just sessionData -> do
                usingHState ctx (setMasterSecret rver ClientRole $ sessionSecret sessionData)
                return $ RecvStateNext expectChangeCipher
onServerHello _ _ _ p = unexpected (show p) (Just "server hello")

processCertificate :: ClientParams -> Context -> Handshake -> IO (RecvState IO)
processCertificate cparams ctx (Certificates certs) = do
    -- run certificate recv hook
    ctxWithHooks ctx (\hooks -> hookRecvCertificates hooks certs)
    -- then run certificate validation
    usage <- catchException (wrapCertificateChecks <$> checkCert) rejectOnException
    case usage of
        CertificateUsageAccept        -> checkLeafCertificateKeyUsage
        CertificateUsageReject reason -> certificateRejected reason
    return $ RecvStateHandshake (processServerKeyExchange ctx)
  where shared = clientShared cparams
        checkCert = (onServerCertificate $ clientHooks cparams) (sharedCAStore shared)
                                                                (sharedValidationCache shared)
                                                                (clientServerIdentification cparams)
                                                                certs
        -- also verify that the certificate optional key usage is compatible
        -- with the intended key-exchange.  This check is not delegated to
        -- x509-validation 'checkLeafKeyUsage' because it depends on negotiated
        -- cipher, which is not available from onServerCertificate parameters.
        -- Additionally, with only one shared ValidationCache, x509-validation
        -- would cache validation result based on a key usage and reuse it with
        -- another key usage.
        checkLeafCertificateKeyUsage = do
            cipher <- usingHState ctx getPendingCipher
            case requiredCertKeyUsage cipher of
                []    -> return ()
                flags -> verifyLeafKeyUsage flags certs

processCertificate _ ctx p = processServerKeyExchange ctx p

expectChangeCipher :: Packet -> IO (RecvState IO)
expectChangeCipher ChangeCipherSpec = return $ RecvStateHandshake expectFinish
expectChangeCipher p                = unexpected (show p) (Just "change cipher")

expectFinish :: Handshake -> IO (RecvState IO)
expectFinish (Finished _) = return RecvStateDone
expectFinish p            = unexpected (show p) (Just "Handshake Finished")

processServerKeyExchange :: Context -> Handshake -> IO (RecvState IO)
processServerKeyExchange ctx (ServerKeyXchg origSkx) = do
    cipher <- usingHState ctx getPendingCipher
    processWithCipher cipher origSkx
    return $ RecvStateHandshake (processCertificateRequest ctx)
  where processWithCipher cipher skx =
            case (cipherKeyExchange cipher, skx) of
                (CipherKeyExchange_DHE_RSA, SKX_DHE_RSA dhparams signature) -> do
                    doDHESignature dhparams signature RSA
                (CipherKeyExchange_DHE_DSS, SKX_DHE_DSS dhparams signature) -> do
                    doDHESignature dhparams signature DSS
                (CipherKeyExchange_ECDHE_RSA, SKX_ECDHE_RSA ecdhparams signature) -> do
                    doECDHESignature ecdhparams signature RSA
                (CipherKeyExchange_ECDHE_ECDSA, SKX_ECDHE_ECDSA ecdhparams signature) -> do
                    doECDHESignature ecdhparams signature ECDSA
                (cke, SKX_Unparsed bytes) -> do
                    ver <- usingState_ ctx getVersion
                    case decodeReallyServerKeyXchgAlgorithmData ver cke bytes of
                        Left _        -> throwCore $ Error_Protocol ("unknown server key exchange received, expecting: " ++ show cke, True, HandshakeFailure)
                        Right realSkx -> processWithCipher cipher realSkx
                    -- we need to resolve the result. and recall processWithCipher ..
                (c,_)           -> throwCore $ Error_Protocol ("unknown server key exchange received, expecting: " ++ show c, True, HandshakeFailure)
        doDHESignature dhparams signature signatureType = do
            -- FIXME verify if FF group is one of supported groups
            verified <- digitallySignDHParamsVerify ctx dhparams signatureType signature
            unless verified $ throwCore $ Error_Protocol ("bad " ++ show signatureType ++ " signature for dhparams " ++ show dhparams, True, HandshakeFailure)
            usingHState ctx $ setServerDHParams dhparams

        doECDHESignature ecdhparams signature signatureType = do
            -- FIXME verify if EC group is one of supported groups
            verified <- digitallySignECDHParamsVerify ctx ecdhparams signatureType signature
            unless verified $ throwCore $ Error_Protocol ("bad " ++ show signatureType ++ " signature for ecdhparams", True, HandshakeFailure)
            usingHState ctx $ setServerECDHParams ecdhparams

processServerKeyExchange ctx p = processCertificateRequest ctx p

processCertificateRequest :: Context -> Handshake -> IO (RecvState IO)
processCertificateRequest ctx (CertRequest cTypes sigAlgs dNames) = do
    -- When the server requests a client
    -- certificate, we simply store the
    -- information for later.
    --
    usingHState ctx $ setClientCertRequest (cTypes, sigAlgs, dNames)
    return $ RecvStateHandshake (processServerHelloDone ctx)
processCertificateRequest ctx p = processServerHelloDone ctx p

processServerHelloDone :: Context -> Handshake -> IO (RecvState m)
processServerHelloDone _ ServerHelloDone = return RecvStateDone
processServerHelloDone _ p = unexpected (show p) (Just "server hello data")

-- Unless result is empty, server certificate must be allowed for at least one
-- of the returned values.  Constraints for RSA-based key exchange are relaxed
-- to avoid rejecting certificates having incomplete extension.
requiredCertKeyUsage :: Cipher -> [ExtKeyUsageFlag]
requiredCertKeyUsage cipher =
    case cipherKeyExchange cipher of
        CipherKeyExchange_RSA         -> rsaCompatibility
        CipherKeyExchange_DH_Anon     -> [] -- unrestricted
        CipherKeyExchange_DHE_RSA     -> rsaCompatibility
        CipherKeyExchange_ECDHE_RSA   -> rsaCompatibility
        CipherKeyExchange_DHE_DSS     -> [ KeyUsage_digitalSignature ]
        CipherKeyExchange_DH_DSS      -> [ KeyUsage_keyAgreement ]
        CipherKeyExchange_DH_RSA      -> rsaCompatibility
        CipherKeyExchange_ECDH_ECDSA  -> [ KeyUsage_keyAgreement ]
        CipherKeyExchange_ECDH_RSA    -> rsaCompatibility
        CipherKeyExchange_ECDHE_ECDSA -> [ KeyUsage_digitalSignature ]
        CipherKeyExchange_TLS13       -> [ KeyUsage_digitalSignature ]
  where rsaCompatibility = [ KeyUsage_digitalSignature
                           , KeyUsage_keyEncipherment
                           , KeyUsage_keyAgreement
                           ]

handshakeClient13 :: ClientParams -> Context -> IO ()
handshakeClient13 _cparams ctx = do
    usedCipher <- usingHState ctx getPendingCipher
    let usedHash = cipherHash usedCipher
    handshakeClient13' _cparams ctx usedCipher usedHash

handshakeClient13' :: ClientParams -> Context -> Cipher -> Hash -> IO ()
handshakeClient13' cparams ctx usedCipher usedHash = do
    (resuming, handshakeSecret, clientHandshakeTrafficSecret, serverHandshakeTrafficSecret) <- switchToHandshakeSecret
    rtt0accepted <- recvEncryptedExtensions
    unless resuming recvCertAndVerify
    recvFinished serverHandshakeTrafficSecret
    hChSf <- transcriptHash ctx
    when rtt0accepted $ do
        eoed <- writeHandshakePacket13 ctx EndOfEarlyData13
        sendBytes13 ctx eoed
    -- putStrLn "---- setTxState ctx usedHash usedCipher clientHandshakeTrafficSecret"
    rawFinished <- makeFinished ctx usedHash clientHandshakeTrafficSecret
    setTxState ctx usedHash usedCipher clientHandshakeTrafficSecret
    writeHandshakePacket13 ctx rawFinished >>= sendBytes13 ctx
    masterSecret <- switchToTrafficSecret handshakeSecret hChSf
    setResumptionSecret masterSecret
    setEstablished ctx Established
  where
    hashSize = hashDigestSize usedHash
    zero = B.replicate hashSize 0

    switchToHandshakeSecret = do
        ecdhe <- calcSharedKey
        (earlySecret, resuming) <- makeEarlySecret
        let handshakeSecret = hkdfExtract usedHash (deriveSecret usedHash earlySecret "derived" (hash usedHash "")) ecdhe
        hChSh <- transcriptHash ctx
        let clientHandshakeTrafficSecret = deriveSecret usedHash handshakeSecret "c hs traffic" hChSh
            serverHandshakeTrafficSecret = deriveSecret usedHash handshakeSecret "s hs traffic" hChSh
        -- putStrLn $ "earlySecret: " ++ showBytesHex earlySecret
        -- putStrLn $ "handshakeSecret: " ++ showBytesHex handshakeSecret
        -- putStrLn $ "hChSh: " ++ showBytesHex hChSh
        -- usingHState ctx getHandshakeMessages >>= mapM_ (putStrLn . showBytesHex)
        -- dumpKey ctx "SERVER_HANDSHAKE_TRAFFIC_SECRET" serverHandshakeTrafficSecret
        -- dumpKey ctx "CLIENT_HANDSHAKE_TRAFFIC_SECRET" clientHandshakeTrafficSecret
        setRxState ctx usedHash usedCipher serverHandshakeTrafficSecret
        return (resuming, handshakeSecret, clientHandshakeTrafficSecret, serverHandshakeTrafficSecret)

    switchToTrafficSecret handshakeSecret hChSf = do
        let masterSecret = hkdfExtract usedHash (deriveSecret usedHash handshakeSecret "derived" (hash usedHash "")) zero
        let clientApplicationTrafficSecret0 = deriveSecret usedHash masterSecret "c ap traffic" hChSf
            serverApplicationTrafficSecret0 = deriveSecret usedHash masterSecret "s ap traffic" hChSf
            exporterMasterSecret = deriveSecret usedHash masterSecret "exp master" hChSf
        usingState_ ctx $ setExporterMasterSecret exporterMasterSecret
        -- putStrLn $ "hChSf: " ++ showBytesHex hChSf
        -- putStrLn $ "masterSecret: " ++ showBytesHex masterSecret
        -- dumpKey ctx "SERVER_TRAFFIC_SECRET_0" serverApplicationTrafficSecret0
        -- dumpKey ctx "CLIENT_TRAFFIC_SECRET_0" clientApplicationTrafficSecret0
        -- putStrLn "---- setTxState ctx usedHash usedCipher clientApplicationTrafficSecret0"
        setTxState ctx usedHash usedCipher clientApplicationTrafficSecret0
        setRxState ctx usedHash usedCipher serverApplicationTrafficSecret0
        return masterSecret

    calcSharedKey = do
        serverKeyShare <- do
            mks <- usingState_ ctx getTLS13KeyShare
            case mks of
              Just (KeyShareServerHello ks) -> return ks
              _                             -> throwCore $ Error_Protocol ("key exchange not implemented", True, HandshakeFailure)
        usingHState ctx $ setNegotiatedGroup $ keyShareEntryGroup serverKeyShare
        usingHState ctx getGroupPrivate >>= fromServerKeyShare serverKeyShare

    makeEarlySecret = do
        secret <- usingHState ctx getTLS13Secret
        case secret of
          EarlySecret sec -> do
              mSelectedIdentity <- usingState_ ctx getTLS13PreSharedKey
              case mSelectedIdentity of
                Nothing                          -> do
                    return (hkdfExtract usedHash zero zero, False)
                Just (PreSharedKeyServerHello 0) -> do
                    usingHState ctx $ setTLS13HandshakeMode PreSharedKey
                    return (sec, True)
                Just _                           -> throwCore $ Error_Protocol ("selected identity out of range", True, IllegalParameter)
          _ -> return (hkdfExtract usedHash zero zero, False)

    recvEncryptedExtensions = do
        ee@(EncryptedExtensions13 eexts) <- recvHandshake13 ctx
        setALPN ctx eexts
        updateHandshake13 ctx ee
        st <- usingHState ctx getTLS13RTT0Status
        if st == RTT0Sent then
            case extensionLookup extensionID_EarlyData eexts of
              Just _  -> do
                  usingHState ctx $ setTLS13HandshakeMode RTT0
                  usingHState ctx $ setTLS13RTT0Status RTT0Accepted
                  return True
              Nothing -> do
                  usingHState ctx $ setTLS13HandshakeMode RTT0
                  usingHState ctx $ setTLS13RTT0Status RTT0Rejected
                  return False
          else
            return False

    recvCertAndVerify = do
        cert <- recvHandshake13 ctx
        let Certificate13 _ cc@(CertificateChain certChain) _ = cert
        _ <- processCertificate cparams ctx (Certificates cc)
        updateHandshake13 ctx cert
        pubkey <- case certChain of
                    [] -> throwCore $ Error_Protocol ("server certificate missing", True, HandshakeFailure)
                    c:_ -> return $ certPubKey $ getCertificate c
        certVerify <- recvHandshake13 ctx
        let CertVerify13 ss sig = certVerify
        hChSc <- transcriptHash ctx
        checkServerCertVerify ss sig pubkey hChSc
        updateHandshake13 ctx certVerify

    recvFinished serverHandshakeTrafficSecret = do
        finished <- recvHandshake13 ctx
        hChSv <- transcriptHash ctx
        let verifyData' = makeVerifyData usedHash serverHandshakeTrafficSecret hChSv
        let Finished13 verifyData = finished
        when (verifyData' /= verifyData) $
            throwCore $ Error_Protocol ("cannot verify finished", True, HandshakeFailure)
        updateHandshake13 ctx finished

    setResumptionSecret masterSecret = do
        hChCf <- transcriptHash ctx
        let resumptionMasterSecret = deriveSecret usedHash masterSecret "res master" hChCf
        usingHState ctx $ setTLS13Secret $ ResuptionSecret resumptionMasterSecret

recvHandshake13 :: Context -> IO Handshake13
recvHandshake13 ctx = do
    msgs <- usingHState ctx getTLS13HandshakeMsgs
    case msgs of
        [] -> do
            epkt <- recvPacket13 ctx
            case epkt of
                Right (Handshake13 [])     -> recvHandshake13 ctx
                Right (Handshake13 (h:hs)) -> do
                    usingHState ctx $ setTLS13HandshakeMsgs hs
                    return h
                Right ChangeCipherSpec13   -> recvHandshake13 ctx
                x                          -> error $ show x
        h:hs -> do
            usingHState ctx $ setTLS13HandshakeMsgs hs
            return h

setALPN :: Context -> [ExtensionRaw] -> IO ()
setALPN ctx exts = case extensionLookup extensionID_ApplicationLayerProtocolNegotiation exts >>= extensionDecode MsgTServerHello of
    Just (ApplicationLayerProtocolNegotiation [proto]) -> usingState_ ctx $ do
        mprotos <- getClientALPNSuggest
        case mprotos of
            Just protos -> when (proto `elem` protos) $ do
                setExtensionALPN True
                setNegotiatedProtocol proto
            _ -> return ()
    _ -> return ()
