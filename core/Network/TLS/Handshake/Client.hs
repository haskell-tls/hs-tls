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
import Network.TLS.Measurement
import Network.TLS.Wire (encodeWord16)
import Network.TLS.Util (bytesEq)
import Network.TLS.Types
import Network.TLS.X509
import Data.Maybe
import Data.List (find)
import qualified Data.ByteString as B
import Data.ByteString.Char8 ()

import Control.Applicative ((<$>), (<*>))
import Control.Monad.State
import Control.Monad.Error
import Control.Exception (SomeException)
import qualified Control.Exception as E

import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Certificate
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.State

-- client part of handshake. send a bunch of handshake of client
-- values intertwined with response from the server.
handshakeClient :: MonadIO m => ClientParams -> Context -> m ()
handshakeClient cparams ctx = do
    updateMeasure ctx incrementNbHandshakes
    sentExtensions <- sendClientHello
    recvServerHello sentExtensions
    sessionResuming <- usingState_ ctx isSessionResuming
    if sessionResuming
        then sendChangeCipherAndFinish ctx ClientRole
        else do sendClientData cparams ctx
                sendChangeCipherAndFinish ctx ClientRole
                recvChangeCipherAndFinish ctx
    handshakeTerminate ctx
  where params       = ctxParams ctx
        ciphers      = pCiphers params
        compressions = pCompressions params
        getExtensions = sequence [sniExtension,secureReneg,npnExtention] >>= return . catMaybes

        toExtensionRaw :: Extension e => e -> ExtensionRaw
        toExtensionRaw ext = (extensionID ext, extensionEncode ext)

        secureReneg  =
                if pUseSecureRenegotiation params
                then usingState_ ctx (getVerifiedData ClientRole) >>= \vd -> return $ Just $ toExtensionRaw $ SecureRenegotiation vd Nothing
                else return Nothing
        npnExtention = if isJust $ onNPNServerSuggest cparams
                         then return $ Just $ toExtensionRaw $ NextProtocolNegotiation []
                         else return Nothing
        sniExtension = return ((\h -> toExtensionRaw $ ServerName [(ServerNameHostName h)]) <$> clientUseServerName cparams)
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

        recvServerHello sentExts = runRecvState ctx (RecvStateHandshake $ onServerHello ctx cparams sentExts)

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
            certRequested <- usingHState ctx getClientCertRequest
            case certRequested of
                Nothing ->
                    return ()

                Just req -> do
                    certChain <- liftIO $ onCertificateRequest cparams req `E.catch`
                                 throwMiscErrorOnException "certificate request callback failed"

                    usingHState ctx $ setClientCertSent False
                    case certChain of
                        Nothing                       -> sendPacket ctx $ Handshake [Certificates (CertificateChain [])]
                        Just (CertificateChain [], _) -> sendPacket ctx $ Handshake [Certificates (CertificateChain [])]
                        Just (cc@(CertificateChain (c:_)), pk) -> do
                            case certPubKey $ getCertificate c of
                                PubKeyRSA _ -> return ()
                                _           -> throwCore $ Error_Protocol ("no supported certificate type", True, HandshakeFailure)
                            usingHState ctx $ setClientPrivateKey pk
                            usingHState ctx $ setClientCertSent True
                            sendPacket ctx $ Handshake [Certificates cc]

        sendClientKeyXchg = do
            (xver, prerand) <- usingState_ ctx $ (,) <$> getVersion <*> genRandom 46
            let premaster = encodePreMasterSecret xver prerand
            usingHState ctx $ setMasterSecretFromPre xver ClientRole premaster
            encryptedPreMaster <- usingState_ ctx $ do
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
            usedVersion <- usingState_ ctx getVersion

            -- Only send a certificate verify message when we
            -- have sent a non-empty list of certificates.
            --
            certSent <- usingHState ctx $ getClientCertSent
            case certSent of
                True -> do
                    -- Fetch all handshake messages up to now.
                    msgs <- usingHState ctx $ B.concat <$> getHandshakeMessages

                    case usedVersion of
                        SSL3 -> do
                            Just masterSecret <- usingHState ctx $ gets hstMasterSecret
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
                            Just (_, Just hashSigs, _) <- usingHState ctx $ getClientCertRequest
                            let suppHashSigs = pHashSignatures $ ctxParams ctx
                                hashSigs' = filter (\ a -> a `elem` hashSigs) suppHashSigs

                            when (null hashSigs') $ do
                                throwCore $ Error_Protocol ("no hash/signature algorithms in common with the server", True, HandshakeFailure)

                            let hashSig = head hashSigs'
                            hsh <- getHashAndASN1 hashSig

                            sigDig <- usingState_ ctx $ signRSA hsh msgs

                            sendPacket ctx $ Handshake [CertVerify (Just hashSig) (CertVerifyData sigDig)]

                _ -> return ()

processServerExtension :: (ExtensionID, Bytes) -> TLSSt ()
processServerExtension (0xff01, content) = do
    cv <- getVerifiedData ClientRole
    sv <- getVerifiedData ServerRole
    let bs = extensionEncode (SecureRenegotiation cv $ Just sv)
    unless (bs `bytesEq` content) $ throwError $ Error_Protocol ("server secure renegotiation data not matching", True, HandshakeFailure)
    return ()
processServerExtension _ = return ()

throwMiscErrorOnException :: MonadIO m => String -> SomeException -> m a
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
onServerHello :: MonadIO m => Context -> ClientParams -> [ExtensionID] -> Handshake -> m (RecvState m)
onServerHello ctx cparams sentExts (ServerHello rver serverRan serverSession cipher compression exts) = do
    when (rver == SSL2) $ throwCore $ Error_Protocol ("ssl2 is not supported", True, ProtocolVersion)
    case find ((==) rver) allowedvers of
        Nothing -> throwCore $ Error_Protocol ("version " ++ show rver ++ "is not supported", True, ProtocolVersion)
        Just _  -> usingState_ ctx $ setVersion rver
    -- find the compression and cipher methods that the server want to use.
    case (find ((==) cipher . cipherID) ciphers, find ((==) compression . compressionID) compressions) of
        (Nothing,_) -> throwCore $ Error_Protocol ("no cipher in common with the server", True, HandshakeFailure)
        (_,Nothing) -> throwCore $ Error_Protocol ("no compression in common with the server", True, HandshakeFailure)
        (Just cipherAlg, Just compressAlg) ->
            usingHState ctx $ setPendingAlgs cipherAlg compressAlg

    -- intersect sent extensions in client and the received extensions from server.
    -- if server returns extensions that we didn't request, fail.
    when (not $ null $ filter (not . flip elem sentExts . fst) exts) $
        throwCore $ Error_Protocol ("spurious extensions received", True, UnsupportedExtension)

    let resumingSession =
            case clientWantSessionResume cparams of
                Just (sessionId, sessionData) -> if serverSession == Session (Just sessionId) then Just sessionData else Nothing
                Nothing                       -> Nothing
    usingState_ ctx $ do
        setSession serverSession (isJust resumingSession)
        mapM_ processServerExtension exts
        setVersion rver
    usingHState ctx $ setServerRandom serverRan

    case extensionDecode False `fmap` (lookup extensionID_NextProtocolNegotiation exts) of
        Just (Just (NextProtocolNegotiation protos)) -> usingState_ ctx $ do
            setExtensionNPN True
            setServerNextProtocolSuggest protos
        _ -> return ()

    case resumingSession of
        Nothing          -> return $ RecvStateHandshake (processCertificate ctx)
        Just sessionData -> do
            usingHState ctx (setMasterSecret rver ClientRole $ sessionSecret sessionData)
            return $ RecvStateNext expectChangeCipher
  where params       = ctxParams ctx
        allowedvers  = pAllowedVersions params
        ciphers      = pCiphers params
        compressions = pCompressions params
onServerHello _ _ _ p = unexpected (show p) (Just "server hello")

processCertificate :: MonadIO m => Context -> Handshake -> m (RecvState m)
processCertificate ctx (Certificates certs) = do
    usage <- liftIO $ E.catch (onCertificatesRecv params certs) rejectOnException
    case usage of
        CertificateUsageAccept        -> return ()
        CertificateUsageReject reason -> certificateRejected reason
    return $ RecvStateHandshake (processServerKeyExchange ctx)
  where params       = ctxParams ctx
processCertificate ctx p = processServerKeyExchange ctx p

expectChangeCipher :: MonadIO m => Packet -> m (RecvState m)
expectChangeCipher ChangeCipherSpec = return $ RecvStateHandshake expectFinish
expectChangeCipher p                = unexpected (show p) (Just "change cipher")

expectFinish :: MonadIO m => Handshake -> m (RecvState m)
expectFinish (Finished _) = return RecvStateDone
expectFinish p            = unexpected (show p) (Just "Handshake Finished")

processServerKeyExchange :: MonadIO m => Context -> Handshake -> m (RecvState m)
processServerKeyExchange ctx (ServerKeyXchg _) = return $ RecvStateHandshake (processCertificateRequest ctx)
processServerKeyExchange ctx p                 = processCertificateRequest ctx p

processCertificateRequest :: MonadIO m => Context -> Handshake -> m (RecvState m)
processCertificateRequest ctx (CertRequest cTypes sigAlgs dNames) = do
    -- When the server requests a client
    -- certificate, we simply store the
    -- information for later.
    --
    usingHState ctx $ setClientCertRequest (cTypes, sigAlgs, dNames)
    return $ RecvStateHandshake (processServerHelloDone ctx)
processCertificateRequest ctx p = processServerHelloDone ctx p

processServerHelloDone :: MonadIO m => Context -> Handshake -> m (RecvState m)
processServerHelloDone _ ServerHelloDone = return RecvStateDone
processServerHelloDone _ p = unexpected (show p) (Just "server hello data")
