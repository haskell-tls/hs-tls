{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.Server.TLS12 (
    recvClientSecondFlight12,
) where

import Control.Monad.State.Strict (gets)
import qualified Data.ByteString as B

import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.Server.Common
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.State
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.Packet hiding (getSession)
import Network.TLS.Parameters
import Network.TLS.Session
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Types
import Network.TLS.X509

recvClientSecondFlight12
    :: ServerParams
    -> Context
    -> Maybe SessionData
    -> IO ()
recvClientSecondFlight12 sparams ctx resumeSessionData = do
    case resumeSessionData of
        Nothing -> do
            recvClientCCC sparams ctx
            mticket <- sessionEstablished ctx
            case mticket of
                Nothing -> return ()
                Just ticket ->
                    sendPacket ctx $ Handshake [NewSessionTicket 3600 ticket] -- xxx fixme
            sendChangeCipherAndFinish ctx ServerRole
        Just _ -> do
            _ <- sessionEstablished ctx
            recvChangeCipherAndFinish ctx
    handshakeDone12 ctx

sessionEstablished :: Context -> IO (Maybe Ticket)
sessionEstablished ctx = do
    session <- usingState_ ctx getSession
    -- only callback the session established if we have a session
    case session of
        Session (Just sessionId) -> do
            sessionData <- getSessionData ctx
            let sessionId' = B.copy sessionId
            sessionEstablish
                (sharedSessionManager $ ctxShared ctx)
                sessionId'
                (fromJust sessionData)
        _ -> return Nothing -- never reach

-- | receive Client data in handshake until the Finished handshake.
--
--      <- [certificate]
--      <- client key xchg
--      <- [cert verify]
--      <- change cipher
--      <- finish
recvClientCCC :: ServerParams -> Context -> IO ()
recvClientCCC sparams ctx = runRecvState ctx (RecvStateHandshake expectClientCertificate)
  where
    expectClientCertificate (Certificates certs) = do
        clientCertificate sparams ctx certs
        processCertificates ctx ServerRole certs

        -- FIXME: We should check whether the certificate
        -- matches our request and that we support
        -- verifying with that certificate.

        return $ RecvStateHandshake expectClientKeyExchange
    expectClientCertificate p = expectClientKeyExchange p

    -- cannot use RecvStateHandshake, as the next message could be a ChangeCipher,
    -- so we must process any packet, and in case of handshake call processHandshake manually.
    expectClientKeyExchange (ClientKeyXchg ckx) = do
        processClientKeyXchg ctx ckx
        return $ RecvStatePacket expectCertificateVerify
    expectClientKeyExchange p = unexpected (show p) (Just "client key exchange")

    -- Check whether the client correctly signed the handshake.
    -- If not, ask the application on how to proceed.
    --
    expectCertificateVerify (Handshake [hs@(CertVerify dsig)]) = do
        processHandshake ctx hs

        certs <- checkValidClientCertChain ctx "change cipher message expected"

        usedVersion <- usingState_ ctx getVersion
        -- Fetch all handshake messages up to now.
        msgs <- usingHState ctx $ B.concat <$> getHandshakeMessages

        pubKey <- usingHState ctx getRemotePublicKey
        checkDigitalSignatureKey usedVersion pubKey

        verif <- checkCertificateVerify ctx usedVersion pubKey msgs dsig
        clientCertVerify sparams ctx certs verif
        return $ RecvStatePacket $ expectChangeCipher ctx
    expectCertificateVerify p = do
        chain <- usingHState ctx getClientCertChain
        case chain of
            Just cc
                | isNullCertificateChain cc -> return ()
                | otherwise ->
                    throwCore $ Error_Protocol "cert verify message missing" UnexpectedMessage
            Nothing -> return ()
        expectChangeCipher ctx p

clientCertVerify :: ServerParams -> Context -> CertificateChain -> Bool -> IO ()
clientCertVerify sparams ctx certs verif = do
    if verif
        then do
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
            res <- onUnverifiedClientCert (serverHooks sparams)
            if res
                then do
                    -- When verification fails, but the
                    -- application callbacks accepts, we
                    -- also commit the client certificate
                    -- chain to the context.
                    usingState_ ctx $ setClientCertificateChain certs
                else decryptError "verification failed"

recvChangeCipherAndFinish :: Context -> IO ()
recvChangeCipherAndFinish ctx = runRecvState ctx $ RecvStatePacket $ expectChangeCipher ctx

expectChangeCipher :: Context -> Packet -> IO (RecvState IO)
expectChangeCipher ctx ChangeCipherSpec = do
    return $ RecvStateHandshake $ expectFinished ctx
expectChangeCipher _ p = unexpected (show p) (Just "change cipher")

-- process the client key exchange message. the protocol expects the initial
-- client version received in ClientHello, not the negotiated version.
-- in case the version mismatch, generate a random master secret
processClientKeyXchg :: Context -> ClientKeyXchgAlgorithmData -> IO ()
processClientKeyXchg ctx (CKX_RSA encryptedPremaster) = do
    (rver, role, random) <- usingState_ ctx $ do
        (,,) <$> getVersion <*> getRole <*> genRandom 48
    ePremaster <- decryptRSA ctx encryptedPremaster
    masterSecret <- usingHState ctx $ do
        expectedVer <- gets hstClientVersion
        case ePremaster of
            Left _ -> setMasterSecretFromPre rver role random
            Right premaster -> case decodePreMasterSecret premaster of
                Left _ -> setMasterSecretFromPre rver role random
                Right (ver, _)
                    | ver /= expectedVer -> setMasterSecretFromPre rver role random
                    | otherwise -> setMasterSecretFromPre rver role premaster
    logKey ctx (MasterSecret masterSecret)
processClientKeyXchg ctx (CKX_DH clientDHValue) = do
    rver <- usingState_ ctx getVersion
    role <- usingState_ ctx getRole

    serverParams <- usingHState ctx getServerDHParams
    let params = serverDHParamsToParams serverParams
    unless (dhValid params $ dhUnwrapPublic clientDHValue) $
        throwCore $
            Error_Protocol "invalid client public key" IllegalParameter

    dhpriv <- usingHState ctx getDHPrivate
    let premaster = dhGetShared params dhpriv clientDHValue
    masterSecret <- usingHState ctx $ setMasterSecretFromPre rver role premaster
    logKey ctx (MasterSecret masterSecret)
processClientKeyXchg ctx (CKX_ECDH bytes) = do
    ServerECDHParams grp _ <- usingHState ctx getServerECDHParams
    case decodeGroupPublic grp bytes of
        Left _ ->
            throwCore $
                Error_Protocol "client public key cannot be decoded" IllegalParameter
        Right clipub -> do
            srvpri <- usingHState ctx getGroupPrivate
            case groupGetShared clipub srvpri of
                Just premaster -> do
                    rver <- usingState_ ctx getVersion
                    role <- usingState_ ctx getRole
                    masterSecret <- usingHState ctx $ setMasterSecretFromPre rver role premaster
                    logKey ctx (MasterSecret masterSecret)
                Nothing ->
                    throwCore $
                        Error_Protocol "cannot generate a shared secret on ECDH" IllegalParameter
