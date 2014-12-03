{-# LANGUAGE DeriveDataTypeable, OverloadedStrings #-}
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
import Network.TLS.Context.Internal
import Network.TLS.Session
import Network.TLS.Struct
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Credentials
import Network.TLS.Crypto.ECDH
import Network.TLS.Extension
import Network.TLS.Util (catchException, fromJust)
import Network.TLS.IO
import Network.TLS.Types
import Network.TLS.State hiding (getNegotiatedProtocol)
import Network.TLS.Handshake.State
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.Key
import Network.TLS.Measurement
import Data.Maybe (isJust)
import Data.List (intersect, sortBy)
import qualified Data.ByteString as B
import Data.ByteString.Char8 ()

import Control.Applicative ((<$>))
import Control.Monad.State

import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Certificate
import Network.TLS.X509

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
--      <- [NPN]
--      <- finish             -> finish
--      -> change cipher      <- change cipher
--      -> finish             <- finish
--
handshakeServerWith :: ServerParams -> Context -> Handshake -> IO ()
handshakeServerWith sparams ctx clientHello@(ClientHello clientVersion _ clientSession ciphers compressions exts _) = do
    -- check if policy allow this new handshake to happens
    handshakeAuthorized <- withMeasure ctx (onNewHandshake $ serverHooks sparams)
    unless handshakeAuthorized (throwCore $ Error_HandshakePolicy "server: handshake denied")
    updateMeasure ctx incrementNbHandshakes

    -- Handle Client hello
    processHandshake ctx clientHello

    when (clientVersion == SSL2) $ throwCore $ Error_Protocol ("ssl2 is not supported", True, ProtocolVersion)
    chosenVersion <- case findHighestVersionFrom clientVersion (supportedVersions $ ctxSupported ctx) of
                        Nothing -> throwCore $ Error_Protocol ("client version " ++ show clientVersion ++ " is not supported", True, ProtocolVersion)
                        Just v  -> return v

    when (commonCipherIDs == []) $ throwCore $
        Error_Protocol ("no cipher in common with the client", True, HandshakeFailure)
    when (null commonCompressions) $ throwCore $
        Error_Protocol ("no compression in common with the client", True, HandshakeFailure)

    let ciphersFilteredVersion = filter (cipherAllowedForVersion chosenVersion) commonCiphers
        usedCipher = (onCipherChoosing $ serverHooks sparams) chosenVersion ciphersFilteredVersion
        creds = sharedCredentials $ ctxShared ctx
    cred <- case cipherKeyExchange usedCipher of
                CipherKeyExchange_RSA     -> return $ credentialsFindForDecrypting creds
                CipherKeyExchange_DH_Anon -> return $ Nothing
                CipherKeyExchange_DHE_RSA -> return $ credentialsFindForSigning SignatureRSA creds
                CipherKeyExchange_DHE_DSS -> return $ credentialsFindForSigning SignatureDSS creds
                CipherKeyExchange_ECDHE_RSA -> return $ credentialsFindForSigning SignatureRSA creds
                _                         -> throwCore $ Error_Protocol ("key exchange algorithm not implemented", True, HandshakeFailure)

    resumeSessionData <- case clientSession of
            (Session (Just clientSessionId)) -> liftIO $ sessionResume (sharedSessionManager $ ctxShared ctx) clientSessionId
            (Session Nothing)                -> return Nothing

    case extensionDecode False `fmap` (lookup extensionID_ApplicationLayerProtocolNegotiation exts) of
        Just (Just (ApplicationLayerProtocolNegotiation protos)) -> usingState_ ctx $ setClientALPNSuggest protos
        _ -> return ()

    case extensionDecode False `fmap` (lookup extensionID_EllipticCurves exts) of
        Just (Just (EllipticCurvesSupported es)) -> usingState_ ctx $ setClientEllipticCurveSuggest es
        _ -> return ()

    -- Currently, we don't send back EcPointFormats. In this case,
    -- the client chooses EcPointFormat_Uncompressed.
    case extensionDecode False `fmap` (lookup extensionID_EcPointFormats exts) of
        Just (Just (EcPointFormatsSupported fs)) -> usingState_ ctx $ setClientEcPointFormatSuggest fs
        _ -> return ()

    doHandshake sparams cred ctx chosenVersion usedCipher usedCompression clientSession resumeSessionData exts

  where
        commonCipherIDs    = intersect ciphers (map cipherID $ ctxCiphers ctx)
        commonCiphers      = filter (flip elem commonCipherIDs . cipherID) (ctxCiphers ctx)
        commonCompressions = compressionIntersectID (supportedCompressions $ ctxSupported ctx) compressions
        usedCompression    = head commonCompressions


handshakeServerWith _ _ _ = throwCore $ Error_Protocol ("unexpected handshake message received in handshakeServerWith", True, HandshakeFailure)

doHandshake :: ServerParams -> Maybe Credential -> Context -> Version -> Cipher
            -> Compression -> Session -> Maybe SessionData
            -> [(ExtensionID, a)] -> IO ()
doHandshake sparams mcred ctx chosenVersion usedCipher usedCompression clientSession resumeSessionData exts = do
    case resumeSessionData of
        Nothing -> do
            handshakeSendServerData
            liftIO $ contextFlush ctx
            -- Receive client info until client Finished.
            recvClientData sparams ctx
            sendChangeCipherAndFinish (return ()) ctx ServerRole
        Just sessionData -> do
            usingState_ ctx (setSession clientSession True)
            serverhello <- makeServerHello clientSession
            sendPacket ctx $ Handshake [serverhello]
            usingHState ctx $ setMasterSecret chosenVersion ServerRole $ sessionSecret sessionData
            sendChangeCipherAndFinish (return ()) ctx ServerRole
            recvChangeCipherAndFinish ctx
    handshakeTerminate ctx
  where
        clientRequestedNPN = isJust $ lookup extensionID_NextProtocolNegotiation exts
        clientALPNSuggest = isJust $ lookup extensionID_ApplicationLayerProtocolNegotiation exts

        applicationProtocol = do
            protos <- alpn
            if null protos then npn else return protos

        alpn | clientALPNSuggest = do
            suggest <- usingState_ ctx $ getClientALPNSuggest
            case (onALPNClientSuggest $ serverHooks sparams, suggest) of
                (Just io, Just protos) -> do
                    proto <- liftIO $ io protos
                    usingState_ ctx $ do
                        setExtensionALPN True
                        setNegotiatedProtocol proto
                    return $ [ ( extensionID_ApplicationLayerProtocolNegotiation
                                                                                                               , extensionEncode $ ApplicationLayerProtocolNegotiation [proto]) ]
                (_, _)                  -> return []
             | otherwise = return []
        npn = do
            nextProtocols <-
                if clientRequestedNPN
                    then liftIO $ onSuggestNextProtocols $ serverHooks sparams
                    else return Nothing
            case nextProtocols of
                Just protos -> do
                    usingState_ ctx $ do
                        setExtensionNPN True
                        setServerNextProtocolSuggest protos
                    return [ ( extensionID_NextProtocolNegotiation
                             , extensionEncode $ NextProtocolNegotiation protos) ]
                Nothing -> return []


        ---
        -- When the client sends a certificate, check whether
        -- it is acceptable for the application.
        --
        ---
        makeServerHello session = do
            srand <- getStateRNG ctx 32 >>= return . ServerRandom
            case mcred of
                Just (_, privkey) -> usingHState ctx $ setPrivateKey privkey
                _                 -> return () -- return a sensible error

            -- in TLS12, we need to check as well the certificates we are sending if they have in the extension
            -- the necessary bits set.
            secReneg   <- usingState_ ctx getSecureRenegotiation
            secRengExt <- if secReneg
                    then do
                            vf <- usingState_ ctx $ do
                                    cvf <- getVerifiedData ClientRole
                                    svf <- getVerifiedData ServerRole
                                    return $ extensionEncode (SecureRenegotiation cvf $ Just svf)
                            return [ (0xff01, vf) ]
                    else return []
            protoExt <- applicationProtocol
            let extensions = secRengExt ++ protoExt
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
                        CipherKeyExchange_DHE_RSA -> Just <$> generateSKX_DHE SignatureRSA
                        CipherKeyExchange_DHE_DSS -> Just <$> generateSKX_DHE SignatureDSS
                        CipherKeyExchange_ECDHE_RSA -> Just <$> generateSKX_ECDHE SignatureRSA
                        _                         -> return Nothing
            maybe (return ()) (sendPacket ctx . Handshake . (:[]) . ServerKeyXchg) skx

            -- FIXME we don't do this on a Anonymous server

            -- When configured, send a certificate request
            -- with the DNs of all confgure CA
            -- certificates.
            --
            when (serverWantClientCert sparams) $ do
                usedVersion <- usingState_ ctx getVersion
                let certTypes = [ CertificateType_RSA_Sign ]
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
            let dhparams = fromJust "server DHE Params" $ serverDHEParams sparams
            (priv, pub) <- generateDHE ctx dhparams

            let serverParams = ServerDHParams dhparams pub

            usingHState ctx $ setServerDHParams serverParams
            usingHState ctx $ modify $ \hst -> hst { hstDHPrivate = Just priv }
            return (serverParams)

        generateSKX_DHE sigAlg = do
            serverParams  <- setup_DHE
            signatureData <- generateSignedDHParams ctx serverParams

            usedVersion <- usingState_ ctx getVersion
            let mhash = case usedVersion of
                            TLS12 -> case filter ((==) sigAlg . snd) $ supportedHashSignatures $ ctxSupported ctx of
                                          []  -> error ("no hash signature for " ++ show sigAlg)
                                          x:_ -> Just (fst x)
                            _     -> Nothing
            let hashDescr = signatureHashData sigAlg mhash
            signed <- signatureCreate ctx (fmap (\h -> (h, sigAlg)) mhash) hashDescr signatureData

            case sigAlg of
                SignatureRSA -> return $ SKX_DHE_RSA serverParams signed
                SignatureDSS -> return $ SKX_DHE_DSS serverParams signed
                _            -> error ("generate skx_dhe unsupported signature type: " ++ show sigAlg)

        generateSKX_DH_Anon = SKX_DH_Anon <$> setup_DHE

        setup_ECDHE curvename = do
            let ecdhparams = ecdhParams curvename
            (priv, pub) <- generateECDHE ctx ecdhparams

            let serverParams = ServerECDHParams ecdhparams pub

            usingHState ctx $ setServerECDHParams serverParams
            usingHState ctx $ modify $ \hst -> hst { hstECDHPrivate = Just priv }
            return (serverParams)

        generateSKX_ECDHE sigAlg = do
            ncs <- usingState_ ctx $ getClientEllipticCurveSuggest
            let common = availableEllipticCurves `intersect` fromJust "ClientEllipticCurveSuggest" ncs
                -- FIXME: Currently maximum strength is chosen.
                --        There may be a better way to choose EC.
                nc = if null common then error "No common EllipticCurves"
                                    else maximum $ map fromEnumSafe16 common
            serverParams  <- setup_ECDHE nc
            signatureData <- generateSignedECDHParams ctx serverParams

            usedVersion <- usingState_ ctx getVersion
            let mhash = case usedVersion of
                            TLS12 -> case filter ((==) sigAlg . snd) $ supportedHashSignatures $ ctxSupported ctx of
                                          []  -> error ("no hash signature for " ++ show sigAlg)
                                          x:_ -> Just (fst x)
                            _     -> Nothing
            let hashDescr = signatureHashData sigAlg mhash
            signed <- signatureCreate ctx (fmap (\h -> (h, sigAlg)) mhash) hashDescr signatureData

            case sigAlg of
                SignatureRSA -> return $ SKX_ECDHE_RSA serverParams signed
                _            -> error ("generate skx_dhe unsupported signature type: " ++ show sigAlg)

-- | receive Client data in handshake until the Finished handshake.
--
--      <- [certificate]
--      <- client key xchg
--      <- [cert verify]
--      <- change cipher
--      <- [NPN]
--      <- finish
--
recvClientData :: ServerParams -> Context -> IO ()
recvClientData sparams ctx = runRecvState ctx (RecvStateHandshake processClientCertificate)
  where processClientCertificate (Certificates certs) = do
            -- run certificate recv hook
            ctxWithHooks ctx (\hooks -> hookRecvCertificates hooks $ certs)
            -- Call application callback to see whether the
            -- certificate chain is acceptable.
            --
            usage <- liftIO $ catchException (onClientCertificate (serverHooks sparams) certs) rejectOnException
            case usage of
                CertificateUsageAccept        -> return ()
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
        processCertificateVerify (Handshake [hs@(CertVerify dsig@(DigitallySigned mbHashSig _))]) = do
            processHandshake ctx hs

            checkValidClientCertChain "change cipher message expected"

            usedVersion <- usingState_ ctx getVersion
            -- Fetch all handshake messages up to now.
            msgs <- usingHState ctx $ B.concat <$> getHandshakeMessages
            (hashMethod, toVerify) <- prepareCertificateVerifySignatureData ctx usedVersion mbHashSig msgs

            -- Verify the signature.
            verif <- signatureVerifyWithHashDescr ctx SignatureRSA hashMethod toVerify dsig

            case verif of
                True -> do
                    -- When verification succeeds, commit the
                    -- client certificate chain to the context.
                    --
                    Just certs <- usingHState ctx $ getClientCertChain
                    usingState_ ctx $ setClientCertificateChain certs
                    return ()

                False -> do
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
                            Just certs <- usingHState ctx $ getClientCertChain
                            usingState_ ctx $ setClientCertificateChain certs
                        else throwCore $ Error_Protocol ("verification failed", True, BadCertificate)
            return $ RecvStateNext expectChangeCipher

        processCertificateVerify p = do
            chain <- usingHState ctx $ getClientCertChain
            case chain of
                Just cc | isNullCertificateChain cc -> return ()
                        | otherwise                 -> throwCore $ Error_Protocol ("cert verify message missing", True, UnexpectedMessage)
                Nothing -> return ()
            expectChangeCipher p

        expectChangeCipher ChangeCipherSpec = do
            npn <- usingState_ ctx getExtensionNPN
            return $ RecvStateHandshake $ if npn then expectNPN else expectFinish
        expectChangeCipher p                = unexpected (show p) (Just "change cipher")

        expectNPN (HsNextProtocolNegotiation _) = return $ RecvStateHandshake expectFinish
        expectNPN p                             = unexpected (show p) (Just "Handshake NextProtocolNegotiation")

        expectFinish (Finished _) = return RecvStateDone
        expectFinish p            = unexpected (show p) (Just "Handshake Finished")

        checkValidClientCertChain msg = do
            chain <- usingHState ctx $ getClientCertChain
            let throwerror = Error_Protocol (msg , True, UnexpectedMessage)
            case chain of
                Nothing -> throwCore throwerror
                Just cc | isNullCertificateChain cc -> throwCore throwerror
                        | otherwise                 -> return ()

findHighestVersionFrom :: Version -> [Version] -> Maybe Version
findHighestVersionFrom clientVersion allowedVersions =
    case filter (clientVersion >=) $ reverse $ sortBy compare allowedVersions of
        []  -> Nothing
        v:_ -> Just v
