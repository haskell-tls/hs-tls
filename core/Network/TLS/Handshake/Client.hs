{-# LANGUAGE DeriveDataTypeable, OverloadedStrings #-}
-- |
-- Module      : Network.TLS.Handshake.Client
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.Client
    ( handshakeClient
    ) where

import Network.TLS.Crypto
import Network.TLS.Context
import Network.TLS.Struct
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Packet
import Network.TLS.Extension
import Network.TLS.IO
import Network.TLS.State hiding (getNegotiatedProtocol)
import Network.TLS.Sending
import Network.TLS.Receiving
import Network.TLS.Measurement
import Network.TLS.Wire (encodeWord16)
import Data.Maybe
import Data.List (find)
import qualified Data.ByteString as B
import Data.ByteString.Char8 ()

import Data.Certificate.X509(X509, x509Cert, certPubKey, PubKey(PubKeyRSA))

import Control.Applicative ((<$>))
import Control.Monad.State
import Control.Exception (SomeException)
import qualified Control.Exception as E

import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Certificate
import Network.TLS.Handshake.Signature

-- client part of handshake. send a bunch of handshake of client
-- values intertwined with response from the server.
handshakeClient :: MonadIO m => ClientParams -> Context -> m ()
handshakeClient cparams ctx = do
    updateMeasure ctx incrementNbHandshakes
    sentExtensions <- sendClientHello
    recvServerHello sentExtensions
    sessionResuming <- usingState_ ctx isSessionResuming
    if sessionResuming
        then sendChangeCipherAndFinish ctx True
        else do sendClientData cparams ctx
                sendChangeCipherAndFinish ctx True
                recvChangeCipherAndFinish ctx
    handshakeTerminate ctx
    where
                params       = ctxParams ctx
                allowedvers  = pAllowedVersions params
                ciphers      = pCiphers params
                compressions = pCompressions params
                getExtensions = sequence [secureReneg,npnExtention] >>= return . catMaybes

                toExtensionRaw :: Extension e => e -> ExtensionRaw
                toExtensionRaw ext = (extensionID ext, extensionEncode ext)

                secureReneg  =
                        if pUseSecureRenegotiation params
                        then usingState_ ctx (getVerifiedData True) >>= \vd -> return $ Just $ toExtensionRaw $ SecureRenegotiation vd Nothing
                        else return Nothing
                npnExtention = if isJust $ onNPNServerSuggest params
                                 then return $ Just $ toExtensionRaw $ NextProtocolNegotiation []
                                 else return Nothing
                sendClientHello = do
                        crand <- getStateRNG ctx 32 >>= return . ClientRandom
                        let clientSession = Session . maybe Nothing (Just . fst) $ clientWantSessionResume cparams
                        extensions <- getExtensions
                        usingState_ ctx (startHandshakeClient (pConnectVersion params) crand)
                        sendPacket ctx $ Handshake
                                [ ClientHello (pConnectVersion params) crand clientSession (map cipherID ciphers)
                                              (map compressionID compressions) extensions Nothing
                                ]
                        return $ map fst extensions

                expectChangeCipher ChangeCipherSpec = return $ RecvStateHandshake expectFinish
                expectChangeCipher p                = unexpected (show p) (Just "change cipher")
                expectFinish (Finished _) = return RecvStateDone
                expectFinish p            = unexpected (show p) (Just "Handshake Finished")

                recvServerHello sentExts = runRecvState ctx (RecvStateHandshake $ onServerHello sentExts)

                onServerHello :: MonadIO m => [ExtensionID] -> Handshake -> m (RecvState m)
                onServerHello sentExts sh@(ServerHello rver _ serverSession cipher _ exts) = do
                        when (rver == SSL2) $ throwCore $ Error_Protocol ("ssl2 is not supported", True, ProtocolVersion)
                        case find ((==) rver) allowedvers of
                                Nothing -> throwCore $ Error_Protocol ("version " ++ show rver ++ "is not supported", True, ProtocolVersion)
                                Just _  -> usingState_ ctx $ setVersion rver
                        case find ((==) cipher . cipherID) ciphers of
                                Nothing -> throwCore $ Error_Protocol ("no cipher in common with the server", True, HandshakeFailure)
                                Just c  -> usingState_ ctx $ setCipher c

                        -- intersect sent extensions in client and the received extensions from server.
                        -- if server returns extensions that we didn't request, fail.
                        when (not $ null $ filter (not . flip elem sentExts . fst) exts) $
                                throwCore $ Error_Protocol ("spurious extensions received", True, UnsupportedExtension)

                        let resumingSession = case clientWantSessionResume cparams of
                                Just (sessionId, sessionData) -> if serverSession == Session (Just sessionId) then Just sessionData else Nothing
                                Nothing                       -> Nothing
                        usingState_ ctx $ setSession serverSession (isJust resumingSession)
                        usingState_ ctx $ processServerHello sh

                        case extensionDecode False `fmap` (lookup extensionID_NextProtocolNegotiation exts) of
                                Just (Just (NextProtocolNegotiation protos)) -> usingState_ ctx $ do
                                        setExtensionNPN True
                                        setServerNextProtocolSuggest protos
                                _ -> return ()

                        case resumingSession of
                                Nothing          -> return $ RecvStateHandshake processCertificate
                                Just sessionData -> do
                                        usingState_ ctx (setMasterSecret $ sessionSecret sessionData)
                                        return $ RecvStateNext expectChangeCipher
                onServerHello _ p = unexpected (show p) (Just "server hello")

                processCertificate :: MonadIO m => Handshake -> m (RecvState m)
                processCertificate (Certificates certs) = do
                        usage <- liftIO $ E.catch (onCertificatesRecv params $ certs) rejectOnException
                        case usage of
                                CertificateUsageAccept        -> return ()
                                CertificateUsageReject reason -> certificateRejected reason
                        return $ RecvStateHandshake processServerKeyExchange

                processCertificate p = processServerKeyExchange p

                processServerKeyExchange :: MonadIO m => Handshake -> m (RecvState m)
                processServerKeyExchange (ServerKeyXchg _) = return $ RecvStateHandshake processCertificateRequest
                processServerKeyExchange p                 = processCertificateRequest p

                processCertificateRequest :: MonadIO m => Handshake -> m (RecvState m)
                processCertificateRequest (CertRequest cTypes sigAlgs dNames) = do
                        -- When the server requests a client
                        -- certificate, we simply store the
                        -- information for later.
                        --
                        usingState_ ctx $ setClientCertRequest (cTypes, sigAlgs, dNames)
                        return $ RecvStateHandshake processServerHelloDone
                processCertificateRequest p = processServerHelloDone p

                processServerHelloDone ServerHelloDone = return RecvStateDone
                processServerHelloDone p = unexpected (show p) (Just "server hello data")

-- | send client Data after receiving all server data (hello/certificates/key).
--
--       -> [certificate]
--       -> client key exchange
--       -> [cert verify]
sendClientData :: MonadIO m => ClientParams -> Context -> m ()
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
                certRequested <- usingState_ ctx getClientCertRequest
                case certRequested of
                    Nothing ->
                        return ()

                    Just req -> do
                        certChain <- liftIO $ onCertificateRequest cparams req `E.catch`
                                     throwMiscErrorOnException "certificate request callback failed"

                        case certChain of
                            (_, Nothing) : _ ->
                                  throwCore $ Error_Misc "no private key available"
                            (cert, Just pk) : _ -> do
                                case certPubKey $ x509Cert cert of
                                    PubKeyRSA _ -> return ()
                                    _           ->
                                        throwCore $ Error_Protocol ("no supported certificate type", True, HandshakeFailure)
                                usingState_ ctx $ setClientPrivateKey pk
                            _ ->
                                return ()

                        usingState_ ctx $ setClientCertSent (not $ null certChain)
                        sendPacket ctx $ Handshake [Certificates $ map fst certChain]


            sendClientKeyXchg = do
                    encryptedPreMaster <- usingState_ ctx $ do
                            xver       <- stVersion <$> get
                            prerand    <- genTLSRandom 46
                            let premaster = encodePreMasterSecret xver prerand
                            setMasterSecretFromPre premaster

                            -- SSL3 implementation generally forget this length field since it's redundant,
                            -- however TLS10 make it clear that the length field need to be present.
                            e <- encryptRSA premaster
                            let extra = if xver < TLS10
                                    then B.empty
                                    else encodeWord16 $ fromIntegral $ B.length e
                            return $ extra `B.append` e
                    sendPacket ctx $ Handshake [ClientKeyXchg encryptedPreMaster]

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
                usedVersion <- usingState_ ctx $ stVersion <$> get

                -- Only send a certificate verify message when we
                -- have sent a non-empty list of certificates.
                --
                certSent <- usingState_ ctx $ getClientCertSent
                case certSent of
                    Just True -> do
                        -- Fetch all handshake messages up to now.
                        msgs <- usingState_ ctx $ B.concat <$> getHandshakeMessages

                        case usedVersion of
                            SSL3 -> do
                                Just masterSecret <- usingState_ ctx $ getMasterSecret
                                let digest = generateCertificateVerify_SSL masterSecret (hashUpdate (hashInit hashMD5SHA1) msgs)
                                    hsh = HashDescr id id

                                sigDig <- usingState_ ctx $ signRSA hsh digest
                                sendPacket ctx $ Handshake [CertVerify Nothing (CertVerifyData sigDig)]

                            x | x == TLS10 || x == TLS11 -> do
                                let hashf bs = hashFinal (hashUpdate (hashInit hashMD5SHA1) bs)
                                    hsh = HashDescr hashf id

                                sigDig <- usingState_ ctx $ signRSA hsh msgs
                                sendPacket ctx $ Handshake [CertVerify Nothing (CertVerifyData sigDig)]

                            _ -> do
                                Just (_, Just hashSigs, _) <- usingState_ ctx $ getClientCertRequest
                                let suppHashSigs = pHashSignatures $ ctxParams ctx
                                    hashSigs' = filter (\ a -> a `elem` hashSigs) suppHashSigs
                                liftIO $ putStrLn $ " supported hash sig algorithms: " ++ show hashSigs'

                                when (null hashSigs') $ do
                                    throwCore $ Error_Protocol ("no hash/signature algorithms in common with the server", True, HandshakeFailure)

                                let hashSig = head hashSigs'
                                hsh <- getHashAndASN1 hashSig

                                sigDig <- usingState_ ctx $ signRSA hsh msgs

                                sendPacket ctx $ Handshake [CertVerify (Just hashSig) (CertVerifyData sigDig)]

                    _ -> return ()



throwMiscErrorOnException :: MonadIO m => String -> SomeException -> m a
throwMiscErrorOnException msg e =
  throwCore $ Error_Misc $ msg ++ ": " ++ show e
