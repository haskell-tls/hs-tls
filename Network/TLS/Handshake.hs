{-# LANGUAGE DeriveDataTypeable, OverloadedStrings #-}
-- |
-- Module      : Network.TLS.Handshake
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake
    ( handshake
    , handshakeServerWith
    , handshakeClient
    , HandshakeFailed(..)
    ) where

import Text.Printf
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
import Network.TLS.Sending
import Network.TLS.Receiving
import Network.TLS.Measurement
import Network.TLS.Wire (encodeWord16)
import Data.Maybe
import Data.Data
import Data.List (intersect, find, intercalate)
import qualified Data.ByteString as B
import Data.ByteString.Char8 ()

import Data.Certificate.X509(X509, certSubjectDN, x509Cert, certPubKey, PubKey(PubKeyRSA))

import qualified Crypto.Hash.SHA224 as SHA224
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA384 as SHA384
import qualified Crypto.Hash.SHA512 as SHA512

import Control.Applicative ((<$>))
import Control.Monad.State
import Control.Exception (throwIO, Exception(), fromException, catch, SomeException)
import Prelude hiding (catch)

data HandshakeFailed = HandshakeFailed TLSError
        deriving (Show,Eq,Typeable)

instance Exception HandshakeFailed

handshakeFailed :: TLSError -> IO ()
handshakeFailed err = throwIO $ HandshakeFailed err

recvPacketHandshake :: MonadIO m => Context -> m [Handshake]
recvPacketHandshake ctx = do
        pkts <- recvPacket ctx
        case pkts of
                Right (Handshake l) -> return l
                Right x             -> fail ("unexpected type received. expecting handshake and got: " ++ show x)
                Left err            -> throwCore err

errorToAlert :: TLSError -> Packet
errorToAlert (Error_Protocol (_, _, ad)) = Alert [(AlertLevel_Fatal, ad)]
errorToAlert _                           = Alert [(AlertLevel_Fatal, InternalError)]

data RecvState m =
          RecvStateNext (Packet -> m (RecvState m))
        | RecvStateHandshake (Handshake -> m (RecvState m))
        | RecvStateDone

runRecvState :: MonadIO m => Context -> RecvState m -> m ()
runRecvState _   (RecvStateDone)   = return ()
runRecvState ctx (RecvStateNext f) = recvPacket ctx >>= either throwCore f >>= runRecvState ctx
runRecvState ctx iniState          = recvPacketHandshake ctx >>= loop iniState >>= runRecvState ctx
        where
                loop :: MonadIO m => RecvState m -> [Handshake] -> m (RecvState m)
                loop recvState []                  = return recvState
                loop (RecvStateHandshake f) (x:xs) = do
                        nstate <- f x
                        usingState_ ctx $ processHandshake x
                        loop nstate xs
                loop _                         _   = unexpected "spurious handshake" Nothing

sendChangeCipherAndFinish :: MonadIO m => Context -> Bool -> m ()
sendChangeCipherAndFinish ctx isClient = do
        sendPacket ctx ChangeCipherSpec

        when isClient $ do
          suggest <- usingState_ ctx $ getServerNextProtocolSuggest
          case (onNPNServerSuggest (ctxParams ctx), suggest) of
            -- client offered, server picked up. send NPN handshake.
            (Just io, Just protos) -> do proto <- liftIO $ io protos
                                         sendPacket ctx (Handshake [HsNextProtocolNegotiation proto])
                                         usingState_ ctx $ setNegotiatedProtocol proto
            -- client offered, server didn't pick up. do nothing.
            (Just _, Nothing) -> return ()
            -- client didn't offer. do nothing.
            (Nothing, _) -> return ()
        liftIO $ contextFlush ctx

        cf <- usingState_ ctx $ getHandshakeDigest isClient
        sendPacket ctx (Handshake [Finished cf])
        liftIO $ contextFlush ctx

recvChangeCipherAndFinish :: MonadIO m => Context -> m ()
recvChangeCipherAndFinish ctx = runRecvState ctx (RecvStateNext expectChangeCipher)
        where
                expectChangeCipher ChangeCipherSpec = return $ RecvStateHandshake expectFinish
                expectChangeCipher p                = unexpected (show p) (Just "change cipher")
                expectFinish (Finished _) = return RecvStateDone
                expectFinish p            = unexpected (show p) (Just "Handshake Finished")

unexpected :: MonadIO m => String -> Maybe [Char] -> m a
unexpected msg expected = throwCore $ Error_Packet_unexpected msg (maybe "" (" expected: " ++) expected)

newSession :: MonadIO m => Context -> m Session
newSession ctx
        | pUseSession $ ctxParams ctx = getStateRNG ctx 32 >>= return . Session . Just
        | otherwise                   = return $ Session Nothing


-- | when a new handshake is done, wrap up & clean up.
handshakeTerminate :: MonadIO m => Context -> m ()
handshakeTerminate ctx = do
        session <- usingState_ ctx getSession
        -- only callback the session established if we have a session
        case session of
                Session (Just sessionId) -> do
                        sessionData <- usingState_ ctx getSessionData
                        withSessionManager (ctxParams ctx) (\s -> liftIO $ sessionEstablish s sessionId (fromJust sessionData))
                _ -> return ()
        -- forget all handshake data now and reset bytes counters.
        usingState_ ctx endHandshake
        updateMeasure ctx resetBytesCounters
        -- mark the secure connection up and running.
        setEstablished ctx True
        return ()

-- client part of handshake. send a bunch of handshake of client
-- values intertwined with response from the server.
handshakeClient :: MonadIO m => ClientParams -> Context -> m ()
handshakeClient cparams ctx = do
        updateMeasure ctx incrementNbHandshakes
        sendClientHello
        recvServerHello
        sessionResuming <- usingState_ ctx isSessionResuming
        if sessionResuming
                then sendChangeCipherAndFinish ctx True
                else do
                        sendCertificate >> sendClientKeyXchg >> sendCertificateVerify
                        sendChangeCipherAndFinish ctx True
                        recvChangeCipherAndFinish ctx
        handshakeTerminate ctx
        where
                params       = ctxParams ctx
                ver          = pConnectVersion params
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
                        usingState_ ctx (startHandshakeClient ver crand)
                        sendPacket ctx $ Handshake
                                [ ClientHello ver crand clientSession (map cipherID ciphers)
                                              (map compressionID compressions) extensions
                                ]

                expectChangeCipher ChangeCipherSpec = return $ RecvStateHandshake expectFinish
                expectChangeCipher p                = unexpected (show p) (Just "change cipher")
                expectFinish (Finished _) = return RecvStateDone
                expectFinish p            = unexpected (show p) (Just "Handshake Finished")

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
                      certChain <- liftIO $ onCertificateRequest cparams req `catch`
                                   throwMiscErrorOnException "certificate request callback failed"

                      case certChain of
                        (_, Nothing) : _ ->
                              throwCore $ Error_Misc "no private key available"
                        (cert, Just pk) : _ -> do
                          case certPubKey $ x509Cert cert of
                            PubKeyRSA _ -> return ()
                            _ ->
                              throwCore $ Error_Protocol ("no supported certificate type", True, HandshakeFailure)
                          usingState_ ctx $ setClientPrivateKey pk
                        _ ->
                          return ()

                      usingState_ ctx $ setClientCertSent (not $ null certChain)
                      sendPacket ctx $ Handshake [Certificates $ map fst certChain]

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
                  -- Only send a certificate verify message when we
                  -- have sent a non-empty list of certificates.
                  --
                  certSent <- usingState_ ctx $ getClientCertSent
                  case certSent of
                    Just True -> do
                      Just (_, mbHashSigs, _) <- usingState_ ctx $ getClientCertRequest
                      (mbHashSig, sigDig) <- if isJust mbHashSigs
                        then do
                          let Just hashSigs = mbHashSigs
                          let suppHashSigs = pHashSignatures $ ctxParams ctx
                          let hashSigs' = filter (\ a -> a `elem` hashSigs) suppHashSigs
                          liftIO $ putStrLn $ " supported hash sig algorithms: " ++ show hashSigs'

                          when (null hashSigs') $ do
                            throwCore $ Error_Protocol ("no hash/signature algorithms in common with the server", True, HandshakeFailure)

                          let hashSig = head hashSigs'
                          hsh <- getHashAndASN1 hashSig

                          -- Fetch all handshake messages up to now.
                          msgs <- usingState_ ctx $ B.concat <$> getHandshakeMessages

                          -- Sign them.
                          sigDig <- usingState_ ctx $ signRSA (Just hsh) msgs

                          return (Just hashSig, sigDig)
                        else do

                          let hashf bs = hashFinal (hashUpdate (hashInit hashMD5SHA1) bs) 
                              hsh = (hashf, "")

                          -- FIXME: Need to check whether the
                          -- server supports RSA signing.

                          -- Fetch all handshake messages up to now.
                          msgs <- usingState_ ctx $ B.concat <$> getHandshakeMessages

                          -- Sign the hash.
                          --
                          sigDig <- usingState_ ctx $ signRSA (Just hsh) msgs
                          return (Nothing, sigDig)

                      -- Send the digest
                      sendPacket ctx $ Handshake [CertVerify mbHashSig sigDig]

                    _ -> return ()

                recvServerHello = runRecvState ctx (RecvStateHandshake onServerHello)

                onServerHello :: MonadIO m => Handshake -> m (RecvState m)
                onServerHello sh@(ServerHello rver _ serverSession cipher _ exts) = do
                        when (rver == SSL2) $ throwCore $ Error_Protocol ("ssl2 is not supported", True, ProtocolVersion)
                        case find ((==) rver) allowedvers of
                                Nothing -> throwCore $ Error_Protocol ("version " ++ show ver ++ "is not supported", True, ProtocolVersion)
                                Just _  -> usingState_ ctx $ setVersion ver
                        case find ((==) cipher . cipherID) ciphers of
                                Nothing -> throwCore $ Error_Protocol ("no cipher in common with the server", True, HandshakeFailure)
                                Just c  -> usingState_ ctx $ setCipher c

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
                onServerHello p = unexpected (show p) (Just "server hello")

                processCertificate :: MonadIO m => Handshake -> m (RecvState m)
                processCertificate (Certificates certs) = do
                        usage <- liftIO $ catch (onCertificatesRecv params $ certs) rejectOnException
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

getHashAndASN1 :: MonadIO m => (HashAlgorithm, SignatureAlgorithm) -> m (B.ByteString -> B.ByteString, B.ByteString)
getHashAndASN1 hashSig = do
  case hashSig of
    (HashSHA224, SignatureRSA) ->
      return (SHA224.hash, "\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c")
    (HashSHA256, SignatureRSA) ->
      return (SHA256.hash, "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20")
    (HashSHA384, SignatureRSA) ->
      return (SHA384.hash, "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30")
    (HashSHA512, SignatureRSA) ->
      return (SHA512.hash, "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40")
    _ ->
      throwCore $ Error_Misc "unsupported hash/sig algorithm"


-- on certificate reject, throw an exception with the proper protocol alert error.
certificateRejected :: MonadIO m => CertificateRejectReason -> m a
certificateRejected CertificateRejectRevoked =
  throwCore $ Error_Protocol ("certificate is revoked", True, CertificateRevoked)
certificateRejected CertificateRejectExpired =
  throwCore $ Error_Protocol ("certificate has expired", True, CertificateExpired)
certificateRejected CertificateRejectUnknownCA =
  throwCore $ Error_Protocol ("certificate has unknown CA", True, UnknownCa)
certificateRejected (CertificateRejectOther s) =
  throwCore $ Error_Protocol ("certificate rejected: " ++ s, True, CertificateUnknown)

rejectOnException :: SomeException -> IO TLSCertificateUsage
rejectOnException e = return $ CertificateUsageReject $ CertificateRejectOther $ show e

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
        when (commonCiphers == []) $
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
                        recvClientData
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
                commonCiphers      = intersect ciphers (map cipherID $ pCiphers params)
                usedCipher         = fromJust $ find (\c -> cipherID c == head commonCiphers) (pCiphers params)
                commonCompressions = compressionIntersectID (pCompressions params) compressions
                usedCompression    = head commonCompressions
                srvCerts           = map fst $ pCertificates params
                privKeys           = map snd $ pCertificates params
                needKeyXchg        = cipherExchangeNeedMoreData $ cipherKeyExchange usedCipher
                clientRequestedNPN = isJust $ lookup extensionID_NextProtocolNegotiation exts

                ---
                recvClientData = runRecvState ctx (RecvStateHandshake processClientCertificate)

                -- When the client sends a certificate, check whether
                -- it is acceptable for the application.
                --
                processClientCertificate (Certificates certs) = do

                  -- Call application callback to see whether the
                  -- certificate chain is acceptable.
                  --
                  usage <- liftIO $ catch (onClientCertificate sparams certs) rejectOnException
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
                processCertificateVerify (Handshake [hs@(CertVerify mbHashSig bs)]) = do
                  usingState_ ctx $ processHandshake hs

                  usedVersion <- usingState_ ctx $ stVersion <$> get

                  case mbHashSig of
                    Just hashSig -> do
                      when (usedVersion < TLS12) $ throwCore $ Error_Protocol ("unexpected hash/sig identifier", True, IllegalParameter)
                      when (not $ hashSig `elem` pHashSignatures (ctxParams ctx)) $ throwCore $ Error_Protocol ("unsupported hash/sig algorithm", True, IllegalParameter)
                    Nothing ->
                      when (usedVersion >= TLS12) $ throwCore $ Error_Protocol ("missing hash/sig identifier", True, IllegalParameter)

                  chain <- usingState_ ctx $ getClientCertChain
                  case chain of
                    Just (_:_) -> return ()
                    _ -> throwCore $ Error_Protocol ("change cipher message expected",
                                                     True, UnexpectedMessage)

                  (sigDig, hsh) <- if usedVersion >= TLS12
                        then do
                          let Just sentHashSig = mbHashSig

                          hsh <- getHashAndASN1 sentHashSig

                          -- Fetch all handshake messages up to now.
                          msgs <- usingState_ ctx $ B.concat <$> getHandshakeMessages

                          return (msgs, Just hsh)
                        else do

                          let hashf bs' = hashFinal (hashUpdate (hashInit hashMD5SHA1) bs') 
                              hsh = (hashf, "")

                          -- FIXME: Need to check whether the
                          -- server supports RSA signing.

                          -- Fetch all handshake messages up to now.
                          msgs <- usingState_ ctx $ B.concat <$> getHandshakeMessages

                          -- FIXME: Need to check whether the
                          -- server supports RSA signing.

                          return (msgs, Just hsh)

                  -- Verify the signature.
                  verif <- usingState_ ctx $ verifyRSA hsh sigDig bs

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
                      let arg = case verif of Left err -> Just err; _ -> Nothing
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
                            Left err ->
                              throwCore $ Error_Protocol (show err, True, DecryptError)
                            _ ->
                              throwCore $ Error_Protocol ("verification failed", True, BadCertificate)
                  return $ RecvStateNext expectChangeCipher

                processCertificateVerify p = do
                  chain <- usingState_ ctx $ getClientCertChain
                  case chain of
                    Just (_:_) ->
                      throwCore $ Error_Protocol ("cert verify message missing",
                                                  True, UnexpectedMessage)
                    _ -> return ()

                  expectChangeCipher p

                expectChangeCipher ChangeCipherSpec = do npn <- usingState_ ctx getExtensionNPN
                                                         return $ RecvStateHandshake $ if npn
                                                                                         then expectNPN
                                                                                         else expectFinish
                expectChangeCipher p                = unexpected (show p) (Just "change cipher")

                expectNPN (HsNextProtocolNegotiation _) = return $ RecvStateHandshake expectFinish
                expectNPN p                             = unexpected (show p) (Just "Handshake NextProtocolNegotiation")

                expectFinish (Finished _) = return RecvStateDone
                expectFinish p            = unexpected (show p) (Just "Handshake Finished")
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

-- after receiving a client hello, we need to redo a handshake
handshakeServer :: MonadIO m => ServerParams -> Context -> m ()
handshakeServer sparams ctx = do
        hss <- recvPacketHandshake ctx
        case hss of
                [ch] -> handshakeServerWith sparams ctx ch
                _    -> fail ("unexpected handshake received, excepting client hello and received " ++ show hss)

-- | Handshake for a new TLS connection
-- This is to be called at the beginning of a connection, and during renegotiation
handshake :: MonadIO m => Context -> m ()
handshake ctx = do
        let handshakeF = case roleParams $ ctxParams ctx of
                            Server sparams -> handshakeServer sparams
                            Client cparams -> handshakeClient cparams
        liftIO $ handleException $ handshakeF ctx
        where
                handleException f = catch f $ \exception -> do
                        let tlserror = maybe (Error_Misc $ show exception) id $ fromException exception
                        setEstablished ctx False
                        sendPacket ctx (errorToAlert tlserror)
                        handshakeFailed tlserror

throwMiscErrorOnException :: MonadIO m => String -> SomeException -> m a
throwMiscErrorOnException msg e =
  throwCore $ Error_Misc $ msg ++ ": " ++ show e


-- Debugging helpers.

dumpMsgs :: MonadIO m => Context -> m ()
dumpMsgs ctx = do
        msgs <- usingState_ ctx $ getHandshakeMessages
        liftIO $ putStrLn $ formatHandshakeMessages msgs

formatHandshakeMessages :: [Bytes] -> String
formatHandshakeMessages bss =
  "=====\n" ++ intercalate "\n" (map form bss) ++ "\n====="
 where
   form :: Bytes -> String
   form bs = printf "bytes: %d\n" (B.length bs) ++ frm bs 0
   frm bs' ofs =
     let (a, b) = B.splitAt 16 bs'
     in if B.null a
        then []
        else printf "%04x: " ofs ++ concatMap (printf "%02x") (B.unpack a) ++ "\n"  ++ frm b (ofs + B.length a)
