{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.Client.TLS12 (
    recvServerFirstFlight12,
    sendClientSecondFlight12,
) where

import Control.Monad.State.Strict
import qualified Data.ByteString as B

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Handshake.Client.Common
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.State
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.Packet hiding (getExtensions)
import Network.TLS.Parameters
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Types
import Network.TLS.Util (catchException)
import Network.TLS.Wire
import Network.TLS.X509

----------------------------------------------------------------

recvServerFirstFlight12 :: ClientParams -> Context -> [Handshake] -> IO ()
recvServerFirstFlight12 cparams ctx hs = do
    resuming <- usingState_ ctx isSessionResuming
    if resuming
        then do
            let st = RecvStatePacket expectChangeCipher
            runRecvStateHS ctx st hs
        else do
            let st = RecvStateHandshake (processCertificate cparams ctx)
            runRecvStateHS ctx st hs

expectChangeCipher :: Packet -> IO (RecvState IO)
expectChangeCipher ChangeCipherSpec = return $ RecvStateHandshake expectFinish
expectChangeCipher p = unexpected (show p) (Just "change cipher")

expectFinish :: Handshake -> IO (RecvState IO)
expectFinish (Finished _) = return RecvStateDone
expectFinish p = unexpected (show p) (Just "Handshake Finished")

processCertificate :: ClientParams -> Context -> Handshake -> IO (RecvState IO)
processCertificate cparams ctx (Certificates certs) = do
    doCertificate cparams ctx certs
    return $ RecvStateHandshake (processServerKeyExchange ctx)
processCertificate _ ctx p = processServerKeyExchange ctx p

processServerKeyExchange :: Context -> Handshake -> IO (RecvState IO)
processServerKeyExchange ctx (ServerKeyXchg origSkx) = do
    doServerKeyExchange ctx origSkx
    return $ RecvStateHandshake (processCertificateRequest ctx)
processServerKeyExchange ctx p = processCertificateRequest ctx p

processCertificateRequest :: Context -> Handshake -> IO (RecvState IO)
processCertificateRequest ctx (CertRequest cTypesSent sigAlgs dNames) = do
    let cTypes = filter (<= lastSupportedCertificateType) cTypesSent
    usingHState ctx $ setCertReqCBdata $ Just (cTypes, Just sigAlgs, dNames)
    return $ RecvStateHandshake (processServerHelloDone ctx)
processCertificateRequest ctx p = do
    usingHState ctx $ setCertReqCBdata Nothing
    processServerHelloDone ctx p

processServerHelloDone :: Context -> Handshake -> IO (RecvState m)
processServerHelloDone _ ServerHelloDone = return RecvStateDone
processServerHelloDone _ p = unexpected (show p) (Just "server hello data")

----------------------------------------------------------------

sendClientSecondFlight12 :: ClientParams -> Context -> IO ()
sendClientSecondFlight12 cparams ctx = do
    sessionResuming <- usingState_ ctx isSessionResuming
    if sessionResuming
        then sendChangeCipherAndFinish ctx ClientRole
        else do
            sendClientData cparams ctx
            sendChangeCipherAndFinish ctx ClientRole
            recvChangeCipherAndFinish ctx
    handshakeDone ctx

----------------------------------------------------------------

-- | TLS 1.2 and below.  Send the client handshake messages that
-- follow the @ServerHello@, etc. except for @CCS@ and @Finished@.
--
-- XXX: Is any buffering done here to combined these messages into
-- a single TCP packet?  Otherwise we're prone to Nagle delays, or
-- in any case needlessly generate multiple small packets, where
-- a single larger packet will do.  The TLS 1.3 code path seems
-- to separating record generation and transmission and sending
-- multiple records in a single packet.
--
--       -> [certificate]
--       -> client key exchange
--       -> [cert verify]
sendClientData :: ClientParams -> Context -> IO ()
sendClientData cparams ctx = sendCertificate >> sendClientKeyXchg >> sendCertificateVerify
  where
    sendCertificate = do
        usingHState ctx $ setClientCertSent False
        clientChain cparams ctx >>= \case
            Nothing -> return ()
            Just cc@(CertificateChain certs) -> do
                unless (null certs) $
                    usingHState ctx $
                        setClientCertSent True
                sendPacket ctx $ Handshake [Certificates cc]

    sendClientKeyXchg = do
        cipher <- usingHState ctx getPendingCipher
        (ckx, setMasterSec) <- case cipherKeyExchange cipher of
            CipherKeyExchange_RSA -> do
                clientVersion <- usingHState ctx $ gets hstClientVersion
                (xver, prerand) <- usingState_ ctx $ (,) <$> getVersion <*> genRandom 46

                let premaster = encodePreMasterSecret clientVersion prerand
                    setMasterSec = setMasterSecretFromPre xver ClientRole premaster
                encryptedPreMaster <- do
                    -- SSL3 implementation generally forget this length field since it's redundant,
                    -- however TLS10 make it clear that the length field need to be present.
                    e <- encryptRSA ctx premaster
                    let extra = encodeWord16 $ fromIntegral $ B.length e
                    return $ extra `B.append` e
                return (CKX_RSA encryptedPreMaster, setMasterSec)
            CipherKeyExchange_DHE_RSA -> getCKX_DHE
            CipherKeyExchange_DHE_DSA -> getCKX_DHE
            CipherKeyExchange_ECDHE_RSA -> getCKX_ECDHE
            CipherKeyExchange_ECDHE_ECDSA -> getCKX_ECDHE
            _ ->
                throwCore $
                    Error_Protocol "client key exchange unsupported type" HandshakeFailure
        sendPacket ctx $ Handshake [ClientKeyXchg ckx]
        masterSecret <- usingHState ctx setMasterSec
        logKey ctx (MasterSecret masterSecret)
      where
        getCKX_DHE = do
            xver <- usingState_ ctx getVersion
            serverParams <- usingHState ctx getServerDHParams

            let params = serverDHParamsToParams serverParams
                ffGroup = findFiniteFieldGroup params
                srvpub = serverDHParamsToPublic serverParams

            unless (maybe False (isSupportedGroup ctx) ffGroup) $ do
                groupUsage <-
                    onCustomFFDHEGroup (clientHooks cparams) params srvpub
                        `catchException` throwMiscErrorOnException "custom group callback failed"
                case groupUsage of
                    GroupUsageInsecure ->
                        throwCore $
                            Error_Protocol "FFDHE group is not secure enough" InsufficientSecurity
                    GroupUsageUnsupported reason ->
                        throwCore $
                            Error_Protocol ("unsupported FFDHE group: " ++ reason) HandshakeFailure
                    GroupUsageInvalidPublic -> throwCore $ Error_Protocol "invalid server public key" IllegalParameter
                    GroupUsageValid -> return ()

            -- When grp is known but not in the supported list we use it
            -- anyway.  This provides additional validation and a more
            -- efficient implementation.
            (clientDHPub, premaster) <-
                case ffGroup of
                    Nothing -> do
                        (clientDHPriv, clientDHPub) <- generateDHE ctx params
                        let premaster = dhGetShared params clientDHPriv srvpub
                        return (clientDHPub, premaster)
                    Just grp -> do
                        usingHState ctx $ setSupportedGroup grp
                        dhePair <- generateFFDHEShared ctx grp srvpub
                        case dhePair of
                            Nothing ->
                                throwCore $
                                    Error_Protocol ("invalid server " ++ show grp ++ " public key") IllegalParameter
                            Just pair -> return pair

            let setMasterSec = setMasterSecretFromPre xver ClientRole premaster
            return (CKX_DH clientDHPub, setMasterSec)

        getCKX_ECDHE = do
            ServerECDHParams grp srvpub <- usingHState ctx getServerECDHParams
            checkSupportedGroup ctx grp
            usingHState ctx $ setSupportedGroup grp
            ecdhePair <- generateECDHEShared ctx srvpub
            case ecdhePair of
                Nothing ->
                    throwCore $
                        Error_Protocol ("invalid server " ++ show grp ++ " public key") IllegalParameter
                Just (clipub, premaster) -> do
                    xver <- usingState_ ctx getVersion
                    let setMasterSec = setMasterSecretFromPre xver ClientRole premaster
                    return (CKX_ECDH $ encodeGroupPublic clipub, setMasterSec)

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
        ver <- usingState_ ctx getVersion

        -- Only send a certificate verify message when we
        -- have sent a non-empty list of certificates.
        --
        certSent <- usingHState ctx getClientCertSent
        when certSent $ do
            pubKey <- getLocalPublicKey ctx
            mhashSig <-
                let cHashSigs = supportedHashSignatures $ ctxSupported ctx
                 in getLocalHashSigAlg ctx signatureCompatible cHashSigs pubKey
            -- Fetch all handshake messages up to now.
            msgs <- usingHState ctx $ B.concat <$> getHandshakeMessages
            sigDig <- createCertificateVerify ctx ver pubKey mhashSig msgs
            sendPacket ctx $ Handshake [CertVerify sigDig]
