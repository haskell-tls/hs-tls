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
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Packet
import Network.TLS.ErrT
import Network.TLS.Extension
import Network.TLS.Extension.Group
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.State hiding (getNegotiatedProtocol)
import Network.TLS.Measurement
import Network.TLS.Wire (encodeWord16)
import Network.TLS.Util (bytesEq, catchException)
import Network.TLS.Types
import Network.TLS.X509
import Data.Maybe
import Data.List (find, intersect)
import qualified Data.ByteString as B
import Data.ByteString.Char8 ()

import Control.Monad.State
import Control.Exception (SomeException)

import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.Certificate
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.State

handshakeClientWith :: ClientParams -> Context -> Handshake -> IO ()
handshakeClientWith cparams ctx HelloRequest = handshakeClient cparams ctx
handshakeClientWith _       _   _            = throwCore $ Error_Protocol ("unexpected handshake message received in handshakeClientWith", True, HandshakeFailure)

-- client part of handshake. send a bunch of handshake of client
-- values intertwined with response from the server.
handshakeClient :: ClientParams -> Context -> IO ()
handshakeClient cparams ctx = do
    updateMeasure ctx incrementNbHandshakes
    sentExtensions <- sendClientHello
    recvServerHello sentExtensions
    sessionResuming <- usingState_ ctx isSessionResuming
    if sessionResuming
        then sendChangeCipherAndFinish sendMaybeNPN ctx ClientRole
        else do sendClientData cparams ctx
                sendChangeCipherAndFinish sendMaybeNPN ctx ClientRole
                recvChangeCipherAndFinish ctx
    handshakeTerminate ctx
  where ciphers      = ctxCiphers ctx
        compressions = supportedCompressions $ ctxSupported ctx
        getExtensions = sequence [sniExtension
                                 ,secureReneg
                                 ,npnExtention
                                 ,alpnExtension
                                 ,curveExtension
                                 ,ecPointExtension
                                 --,sessionTicketExtension
                                 ,signatureAlgExtension
                                 -- ,heartbeatExtension
                                 ]

        toExtensionRaw :: Extension e => e -> ExtensionRaw
        toExtensionRaw ext = ExtensionRaw (extensionID ext) (extensionEncode ext)

        secureReneg  =
                if supportedSecureRenegotiation $ ctxSupported ctx
                then usingState_ ctx (getVerifiedData ClientRole) >>= \vd -> return $ Just $ toExtensionRaw $ SecureRenegotiation vd Nothing
                else return Nothing
        npnExtention = if isJust $ onNPNServerSuggest $ clientHooks cparams
                         then return $ Just $ toExtensionRaw $ NextProtocolNegotiation []
                         else return Nothing
        alpnExtension = do
            mprotos <- onSuggestALPN $ clientHooks cparams
            case mprotos of
                Nothing -> return Nothing
                Just protos -> do
                    usingState_ ctx $ setClientALPNSuggest protos
                    return $ Just $ toExtensionRaw $ ApplicationLayerProtocolNegotiation protos
        sniExtension = if clientUseServerNameIndication cparams
                         then return $ Just $ toExtensionRaw $ ServerName [ServerNameHostName $ fst $ clientServerIdentification cparams]
                         else return Nothing

        curveExtension = return $ Just $ toExtensionRaw $ NegotiatedGroups ((supportedGroups $ ctxSupported ctx) `intersect` availableGroups)
        ecPointExtension = return $ Just $ toExtensionRaw $ EcPointFormatsSupported [EcPointFormat_Uncompressed]
                                --[EcPointFormat_Uncompressed,EcPointFormat_AnsiX962_compressed_prime,EcPointFormat_AnsiX962_compressed_char2]
        --heartbeatExtension = return $ Just $ toExtensionRaw $ HeartBeat $ HeartBeat_PeerAllowedToSend
        --sessionTicketExtension = return $ Just $ toExtensionRaw $ SessionTicket

        signatureAlgExtension = return $ Just $ toExtensionRaw $ SignatureAlgorithms $ supportedHashSignatures $ clientSupported cparams

        sendClientHello = do
            crand <- getStateRNG ctx 32 >>= return . ClientRandom
            let clientSession = Session . maybe Nothing (Just . fst) $ clientWantSessionResume cparams
                highestVer = maximum $ supportedVersions $ ctxSupported ctx
            extensions <- catMaybes <$> getExtensions
            startHandshake ctx highestVer crand
            usingState_ ctx $ setVersionIfUnset highestVer
            sendPacket ctx $ Handshake
                [ ClientHello highestVer crand clientSession (map cipherID (ciphers mempty))
                              (map compressionID compressions) extensions Nothing
                ]
            return $ map (\(ExtensionRaw i _) -> i) extensions

        sendMaybeNPN = do
            suggest <- usingState_ ctx $ getServerNextProtocolSuggest
            case (onNPNServerSuggest $ clientHooks cparams, suggest) of
                -- client offered, server picked up. send NPN handshake.
                (Just io, Just protos) -> do proto <- liftIO $ io protos
                                             sendPacket ctx (Handshake [HsNextProtocolNegotiation proto])
                                             usingState_ ctx $ setNegotiatedProtocol proto
                -- client offered, server didn't pick up. do nothing.
                (Just _, Nothing) -> return ()
                -- client didn't offer. do nothing.
                (Nothing, _) -> return ()

        recvServerHello sentExts = runRecvState ctx recvState
          where recvState = RecvStateNext $ \p ->
                    case p of
                        Handshake hs -> onRecvStateHandshake ctx (RecvStateHandshake $ onServerHello ctx cparams sentExts) hs
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
                    (clientDHPriv, clientDHPub) <- generateDHE ctx (serverDHParamsToParams serverParams)

                    let premaster = dhGetShared (serverDHParamsToParams serverParams)
                                                clientDHPriv
                                                (serverDHParamsToPublic serverParams)
                    usingHState ctx $ setMasterSecretFromPre xver ClientRole premaster

                    return $ CKX_DH clientDHPub

                getCKX_ECDHE = do
                    ServerECDHParams _grp srvpub <- usingHState ctx getServerECDHParams
                    (clipub, premaster) <- generateECDHEShared ctx srvpub
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
            certSent <- usingHState ctx $ getClientCertSent
            case certSent of
                True -> do
                    sigAlg <- getLocalSignatureAlg

                    mhash <- case usedVersion of
                        TLS12 -> do
                            Just (_, Just hashSigs, _) <- usingHState ctx $ getClientCertRequest
                            -- The values in the "signature_algorithms" extension
                            -- are in descending order of preference.
                            -- However here the algorithms are selected according
                            -- to client preference in 'supportedHashSignatures'.
                            let suppHashSigs = supportedHashSignatures $ ctxSupported ctx
                                matchHashSigs = filter (\ a -> snd a == sigAlg) suppHashSigs
                                hashSigs' = filter (\ a -> a `elem` hashSigs) matchHashSigs

                            when (null hashSigs') $
                                throwCore $ Error_Protocol ("no " ++ show sigAlg ++ " hash algorithm in common with the server", True, HandshakeFailure)
                            return $ Just $ fst $ head hashSigs'
                        _     -> return Nothing

                    -- Fetch all handshake messages up to now.
                    msgs   <- usingHState ctx $ B.concat <$> getHandshakeMessages
                    sigDig <- certificateVerifyCreate ctx usedVersion sigAlg mhash msgs
                    sendPacket ctx $ Handshake [CertVerify sigDig]

                _ -> return ()

        getLocalSignatureAlg = do
            pk <- usingHState ctx getLocalPrivateKey
            case pk of
                PrivKeyRSA _   -> return SignatureRSA
                PrivKeyDSA _   -> return SignatureDSS

processServerExtension :: ExtensionRaw -> TLSSt ()
processServerExtension (ExtensionRaw 0xff01 content) = do
    cv <- getVerifiedData ClientRole
    sv <- getVerifiedData ServerRole
    let bs = extensionEncode (SecureRenegotiation cv $ Just sv)
    unless (bs `bytesEq` content) $ throwError $ Error_Protocol ("server secure renegotiation data not matching", True, HandshakeFailure)
    return ()
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
-- 5) process NPN extension
-- 6) if no resume switch to processCertificate SM or in resume switch to expectChangeCipher
--
onServerHello :: Context -> ClientParams -> [ExtensionID] -> Handshake -> IO (RecvState IO)
onServerHello ctx cparams sentExts (ServerHello rver serverRan serverSession cipher compression exts) = do
    when (rver == SSL2) $ throwCore $ Error_Protocol ("ssl2 is not supported", True, ProtocolVersion)
    case find ((==) rver) (supportedVersions $ ctxSupported ctx) of
        Nothing -> throwCore $ Error_Protocol ("server version " ++ show rver ++ " is not supported", True, ProtocolVersion)
        Just _  -> return ()
    -- find the compression and cipher methods that the server want to use.
    cipherAlg <- case find ((==) cipher . cipherID) (ctxCiphers ctx mempty) of
                     Nothing  -> throwCore $ Error_Protocol ("server choose unknown cipher", True, HandshakeFailure)
                     Just alg -> return alg
    compressAlg <- case find ((==) compression . compressionID) (supportedCompressions $ ctxSupported ctx) of
                       Nothing  -> throwCore $ Error_Protocol ("server choose unknown compression", True, HandshakeFailure)
                       Just alg -> return alg

    -- intersect sent extensions in client and the received extensions from server.
    -- if server returns extensions that we didn't request, fail.
    when (not $ null $ filter (not . flip elem sentExts . (\(ExtensionRaw i _) -> i)) exts) $
        throwCore $ Error_Protocol ("spurious extensions received", True, UnsupportedExtension)

    let resumingSession =
            case clientWantSessionResume cparams of
                Just (sessionId, sessionData) -> if serverSession == Session (Just sessionId) then Just sessionData else Nothing
                Nothing                       -> Nothing
    usingState_ ctx $ do
        setSession serverSession (isJust resumingSession)
        mapM_ processServerExtension exts
        setVersion rver
    usingHState ctx $ setServerHelloParameters rver serverRan cipherAlg compressAlg

    case extensionDecode False `fmap` (extensionLookup extensionID_ApplicationLayerProtocolNegotiation exts) of
        Just (Just (ApplicationLayerProtocolNegotiation [proto])) -> usingState_ ctx $ do
            mprotos <- getClientALPNSuggest
            case mprotos of
                Just protos -> when (elem proto protos) $ do
                    setExtensionALPN True
                    setNegotiatedProtocol proto
                _ -> return ()
        _ -> return ()

    case extensionDecode False `fmap` (extensionLookup extensionID_NextProtocolNegotiation exts) of
        Just (Just (NextProtocolNegotiation protos)) -> usingState_ ctx $ do
            alpnDone <- getExtensionALPN
            unless alpnDone $ do
                setExtensionNPN True
                setServerNextProtocolSuggest protos
        _ -> return ()

    case resumingSession of
        Nothing          -> return $ RecvStateHandshake (processCertificate cparams ctx)
        Just sessionData -> do
            usingHState ctx (setMasterSecret rver ClientRole $ sessionSecret sessionData)
            return $ RecvStateNext expectChangeCipher
onServerHello _ _ _ p = unexpected (show p) (Just "server hello")

processCertificate :: ClientParams -> Context -> Handshake -> IO (RecvState IO)
processCertificate cparams ctx (Certificates certs) = do
    -- run certificate recv hook
    ctxWithHooks ctx (\hooks -> hookRecvCertificates hooks $ certs)
    -- then run certificate validation
    usage <- catchException (wrapCertificateChecks <$> checkCert) rejectOnException
    case usage of
        CertificateUsageAccept        -> return ()
        CertificateUsageReject reason -> certificateRejected reason
    return $ RecvStateHandshake (processServerKeyExchange ctx)
  where shared = clientShared cparams
        checkCert = (onServerCertificate $ clientHooks cparams) (sharedCAStore shared)
                                                                (sharedValidationCache shared)
                                                                (clientServerIdentification cparams)
                                                                certs
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
                    doDHESignature dhparams signature SignatureRSA
                (CipherKeyExchange_DHE_DSS, SKX_DHE_DSS dhparams signature) -> do
                    doDHESignature dhparams signature SignatureDSS
                (CipherKeyExchange_ECDHE_RSA, SKX_ECDHE_RSA ecdhparams signature) -> do
                    doECDHESignature ecdhparams signature SignatureRSA
                (CipherKeyExchange_ECDHE_ECDSA, SKX_ECDHE_ECDSA ecdhparams signature) -> do
                    doECDHESignature ecdhparams signature SignatureECDSA
                (cke, SKX_Unparsed bytes) -> do
                    ver <- usingState_ ctx getVersion
                    case decodeReallyServerKeyXchgAlgorithmData ver cke bytes of
                        Left _        -> throwCore $ Error_Protocol ("unknown server key exchange received, expecting: " ++ show cke, True, HandshakeFailure)
                        Right realSkx -> processWithCipher cipher realSkx
                    -- we need to resolve the result. and recall processWithCipher ..
                (c,_)           -> throwCore $ Error_Protocol ("unknown server key exchange received, expecting: " ++ show c, True, HandshakeFailure)
        doDHESignature dhparams signature signatureType = do
            -- TODO verify DHParams
            verified <- digitallySignDHParamsVerify ctx dhparams signatureType signature
            when (not verified) $ throwCore $ Error_Protocol ("bad " ++ show signatureType ++ " for dhparams " ++ show dhparams, True, HandshakeFailure)
            usingHState ctx $ setServerDHParams dhparams

        doECDHESignature ecdhparams signature signatureType = do
            -- TODO verify DHParams
            verified <- digitallySignECDHParamsVerify ctx ecdhparams signatureType signature
            when (not verified) $ throwCore $ Error_Protocol ("bad " ++ show signatureType ++ " for ecdhparams", True, HandshakeFailure)
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
