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

import Network.TLS.Crypto
import Network.TLS.Context
import Network.TLS.Session
import Network.TLS.Struct
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Packet
import Network.TLS.Extension
import Network.TLS.IO
import Network.TLS.State hiding (getNegotiatedProtocol)
import Network.TLS.Receiving
import Network.TLS.Measurement
import Data.Maybe
import Data.List (intersect)
import qualified Data.ByteString as B
import Data.ByteString.Char8 ()

import Data.Certificate.X509(X509, certSubjectDN, x509Cert)

import Control.Applicative ((<$>))
import Control.Monad.State
import qualified Control.Exception as E

import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Certificate

-- Put the server context in handshake mode.
--
-- Expect to receive as first packet a client hello handshake message
--
-- This is just a helper to pop the next message from the recv layer,
-- and call handshakeServerWith.
handshakeServer :: MonadIO m => ServerParams -> Context -> m ()
handshakeServer sparams ctx = do
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
handshakeServerWith :: MonadIO m => ServerParams -> Context -> Handshake -> m ()
handshakeServerWith sparams ctx clientHello@(ClientHello ver _ clientSession ciphers compressions exts) = do
        -- check if policy allow this new handshake to happens
        handshakeAuthorized <- withMeasure ctx (onHandshake $ ctxParams ctx)
        unless handshakeAuthorized (throwCore $ Error_HandshakePolicy "server: handshake denied")
        updateMeasure ctx incrementNbHandshakes

        -- Handle Client hello
        usingState_ ctx $ processHandshake clientHello
        when (ver == SSL2) $ throwCore $ Error_Protocol ("ssl2 is not supported", True, ProtocolVersion)
        when (not $ elem ver (pAllowedVersions params)) $
                throwCore $ Error_Protocol ("version " ++ show ver ++ "is not supported", True, ProtocolVersion)
        when (commonCipherIDs == []) $
                throwCore $ Error_Protocol ("no cipher in common with the client", True, HandshakeFailure)
        when (null commonCompressions) $
                throwCore $ Error_Protocol ("no compression in common with the client", True, HandshakeFailure)
        usingState_ ctx $ modify (\st -> st
                { stVersion     = ver
                , stCipher      = Just usedCipher
                , stCompression = usedCompression
                })

        resumeSessionData <- case clientSession of
                (Session (Just clientSessionId)) -> withSessionManager params (\s -> liftIO $ sessionResume s clientSessionId)
                (Session Nothing)                -> return Nothing
        case resumeSessionData of
                Nothing -> do
                        handshakeSendServerData
                        liftIO $ contextFlush ctx
                        -- Receive client info until client Finished.
                        recvClientData sparams ctx
                        sendChangeCipherAndFinish ctx False
                Just sessionData -> do
                        usingState_ ctx (setSession clientSession True)
                        serverhello <- makeServerHello clientSession
                        sendPacket ctx $ Handshake [serverhello]
                        usingState_ ctx $ setMasterSecret $ sessionSecret sessionData
                        sendChangeCipherAndFinish ctx False
                        recvChangeCipherAndFinish ctx
        handshakeTerminate ctx
        where
                params             = ctxParams ctx
                commonCipherIDs    = intersect ciphers (map cipherID $ pCiphers params)
                commonCiphers      = filter (flip elem commonCipherIDs . cipherID) (pCiphers params)
                usedCipher         = (onCipherChoosing sparams) ver commonCiphers
                commonCompressions = compressionIntersectID (pCompressions params) compressions
                usedCompression    = head commonCompressions
                srvCerts           = map fst $ pCertificates params
                privKeys           = map snd $ pCertificates params
                needKeyXchg        = cipherExchangeNeedMoreData $ cipherKeyExchange usedCipher
                clientRequestedNPN = isJust $ lookup extensionID_NextProtocolNegotiation exts

                ---

                -- When the client sends a certificate, check whether
                -- it is acceptable for the application.
                --
                ---

                makeServerHello session = do
                        srand <- getStateRNG ctx 32 >>= return . ServerRandom
                        case privKeys of
                                (Just privkey : _) -> usingState_ ctx $ setPrivateKey privkey
                                _                  -> return () -- return a sensible error

                        -- in TLS12, we need to check as well the certificates we are sending if they have in the extension
                        -- the necessary bits set.
                        secReneg   <- usingState_ ctx getSecureRenegotiation
                        secRengExt <- if secReneg
                                then do
                                        vf <- usingState_ ctx $ do
                                                cvf <- getVerifiedData True
                                                svf <- getVerifiedData False
                                                return $ extensionEncode (SecureRenegotiation cvf $ Just svf)
                                        return [ (0xff01, vf) ]
                                else return []
                        nextProtocols <-
                          if clientRequestedNPN
                            then liftIO $ onSuggestNextProtocols params
                            else return Nothing
                        npnExt <- case nextProtocols of
                                    Just protos -> do usingState_ ctx $ do setExtensionNPN True
                                                                           setServerNextProtocolSuggest protos
                                                      return [ ( extensionID_NextProtocolNegotiation
                                                               , extensionEncode $ NextProtocolNegotiation protos) ]
                                    Nothing -> return []
                        let extensions = secRengExt ++ npnExt
                        usingState_ ctx (setVersion ver >> setServerRandom srand)
                        return $ ServerHello ver srand session (cipherID usedCipher)
                                                       (compressionID usedCompression) extensions

                handshakeSendServerData = do
                        serverSession <- newSession ctx
                        usingState_ ctx (setSession serverSession False)
                        serverhello   <- makeServerHello serverSession
                        -- send ServerHello & Certificate & ServerKeyXchg & CertReq
                        sendPacket ctx $ Handshake [ serverhello, Certificates srvCerts ]
                        when needKeyXchg $ do
                                let skg = SKX_RSA Nothing
                                sendPacket ctx (Handshake [ServerKeyXchg skg])

                        -- FIXME we don't do this on a Anonymous server

                        -- When configured, send a certificate request
                        -- with the DNs of all confgure CA
                        -- certificates.
                        --
                        when (serverWantClientCert sparams) $ do
                          usedVersion <- usingState_ ctx $ stVersion <$> get
                          let certTypes = [ CertificateType_RSA_Sign ]
                              hashSigs = if usedVersion < TLS12
                                         then Nothing
                                         else Just (pHashSignatures $ ctxParams ctx)
                              creq = CertRequest certTypes hashSigs
                                       (map extractCAname $ serverCACertificates sparams)
                          usingState_ ctx $ setCertReqSent True
                          sendPacket ctx (Handshake [creq])

                        -- Send HelloDone
                        sendPacket ctx (Handshake [ServerHelloDone])

                extractCAname :: X509 -> DistinguishedName
                extractCAname cert = DistinguishedName $ certSubjectDN (x509Cert cert)

handshakeServerWith _ _ _ = fail "unexpected handshake type received. expecting client hello"

-- | receive Client data in handshake until the Finished handshake.
--
--      <- [certificate]
--      <- client key xchg
--      <- [cert verify]
--      <- change cipher
--      <- [NPN]
--      <- finish
--
recvClientData :: MonadIO m => ServerParams -> Context -> m ()
recvClientData sparams ctx = runRecvState ctx (RecvStateHandshake processClientCertificate)
    where
                processClientCertificate (Certificates certs) = do

                  -- Call application callback to see whether the
                  -- certificate chain is acceptable.
                  --
                  usage <- liftIO $ E.catch (onClientCertificate sparams certs) rejectOnException
                  case usage of
                    CertificateUsageAccept        -> return ()
                    CertificateUsageReject reason -> certificateRejected reason

                  -- Remember cert chain for later use.
                  --
                  usingState_ ctx $ setClientCertChain certs

                  -- FIXME: We should check whether the certificate
                  -- matches our request and that we support
                  -- verifying with that certificate.

                  return $ RecvStateHandshake processClientKeyExchange

                processClientCertificate p = processClientKeyExchange p

                processClientKeyExchange (ClientKeyXchg _) = return $ RecvStateNext processCertificateVerify
                processClientKeyExchange p                 = unexpected (show p) (Just "client key exchange")

                -- Check whether the client correctly signed the handshake.
                -- If not, ask the application on how to proceed.
                --
                processCertificateVerify (Handshake [hs@(CertVerify mbHashSig (CertVerifyData bs))]) = do
                    usingState_ ctx $ processHandshake hs
                    chain <- usingState_ ctx $ getClientCertChain
                    case chain of
                        Just (_:_) -> return ()
                        _          -> throwCore $ Error_Protocol ("change cipher message expected", True, UnexpectedMessage)

                    -- Fetch all handshake messages up to now.
                    msgs <- usingState_ ctx $ B.concat <$> getHandshakeMessages

                    usedVersion <- usingState_ ctx $ stVersion <$> get

                    verif <- case usedVersion of
                        SSL3 -> do
                            Just masterSecret <- usingState_ ctx $ getMasterSecret
                            let digest = generateCertificateVerify_SSL masterSecret (hashUpdate (hashInit hashMD5SHA1) msgs)
                                hsh = (id, "")
                            -- Verify the signature.
                            verif <- usingState_ ctx $ verifyRSA hsh digest bs
                            return verif

                        x | x == TLS10 || x == TLS11 -> do
                            let hashf bs' = hashFinal (hashUpdate (hashInit hashMD5SHA1) bs')
                                hsh = (hashf, "")

                            -- Verify the signature.
                            verif <- usingState_ ctx $ verifyRSA hsh msgs bs
                            return verif

                        _ -> do
                            let Just sentHashSig = mbHashSig
                            hsh <- getHashAndASN1 sentHashSig

                            -- Verify the signature.
                            verif <- usingState_ ctx $ verifyRSA hsh msgs bs
                            return verif

                    case verif of
                        Right True -> do
                            -- When verification succeeds, commit the
                            -- client certificate chain to the context.
                            --
                            Just certs <- usingState_ ctx $ getClientCertChain
                            usingState_ ctx $ setClientCertificateChain certs
                            return ()

                        _ -> do
                            -- Either verification failed because of an
                            -- invalid format (with an error message), or
                            -- the signature is wrong.  In either case,
                            -- ask the application -- if it wants to
                            -- proceed, we will do that.
                            --
                            let arg = case verif of
                                    Left err -> Just err
                                    _        -> Nothing
                            res <- liftIO $ onUnverifiedClientCert sparams arg
                            if res
                                then do
                                    -- When verification fails, but the
                                    -- application callbacks accepts, we
                                    -- also commit the client certificate
                                    -- chain to the context.
                                    --
                                    Just certs <- usingState_ ctx $ getClientCertChain
                                    usingState_ ctx $ setClientCertificateChain certs
                                else do
                                    case verif of
                                        Left err -> throwCore $ Error_Protocol (show err, True, DecryptError)
                                        _        -> throwCore $ Error_Protocol ("verification failed", True, BadCertificate)
                    return $ RecvStateNext expectChangeCipher

                processCertificateVerify p = do
                    chain <- usingState_ ctx $ getClientCertChain
                    case chain of
                        Just (_:_) -> throwCore $ Error_Protocol ("cert verify message missing", True, UnexpectedMessage)
                        _          -> return ()
                    expectChangeCipher p

                expectChangeCipher ChangeCipherSpec = do
                    npn <- usingState_ ctx getExtensionNPN
                    return $ RecvStateHandshake $ if npn then expectNPN else expectFinish
                expectChangeCipher p                = unexpected (show p) (Just "change cipher")

                expectNPN (HsNextProtocolNegotiation _) = return $ RecvStateHandshake expectFinish
                expectNPN p                             = unexpected (show p) (Just "Handshake NextProtocolNegotiation")

                expectFinish (Finished _) = return RecvStateDone
                expectFinish p            = unexpected (show p) (Just "Handshake Finished")
