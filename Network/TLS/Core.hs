{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE DeriveDataTypeable, OverloadedStrings #-}
-- |
-- Module      : Network.TLS.Core
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Core
        (
        -- * Internal packet sending and receiving
          sendPacket
        , recvPacket

        -- * Initialisation and Termination of context
        , bye
        , handshake
        , HandshakeFailed(..)
        , ConnectionNotEstablished(..)

        -- * Next Protocol Negotiation
        , getNegotiatedProtocol

        -- * High level API
        , sendData
        , recvData
        , recvData'
        ) where

import Network.TLS.Context
import Network.TLS.Struct
import Network.TLS.Record
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Packet
import qualified Network.TLS.State as S
import Network.TLS.State hiding (getNegotiatedProtocol)
import Network.TLS.Sending
import Network.TLS.Receiving
import Network.TLS.Measurement
import Network.TLS.Wire (encodeWord16)
import Data.Maybe
import Data.Data
import Data.List (intersect, find)
import qualified Data.ByteString as B
import Data.ByteString.Char8 ()
import qualified Data.ByteString.Lazy as L

import Control.Applicative ((<$>))
import Control.Monad.State
import Control.Exception (throwIO, Exception(), fromException, catch, SomeException)
import System.IO.Error (mkIOError, eofErrorType)
import Prelude hiding (catch)

data HandshakeFailed = HandshakeFailed TLSError
        deriving (Show,Eq,Typeable)

data ConnectionNotEstablished = ConnectionNotEstablished
        deriving (Show,Eq,Typeable)

instance Exception HandshakeFailed
instance Exception ConnectionNotEstablished

errorToAlert :: TLSError -> Packet
errorToAlert (Error_Protocol (_, _, ad)) = Alert [(AlertLevel_Fatal, ad)]
errorToAlert _                           = Alert [(AlertLevel_Fatal, InternalError)]

handshakeFailed :: TLSError -> IO ()
handshakeFailed err = throwIO $ HandshakeFailed err

checkValid :: MonadIO m => Context -> m ()
checkValid ctx = do
        established <- ctxEstablished ctx
        unless established $ liftIO $ throwIO ConnectionNotEstablished
        eofed <- ctxEOF ctx
        when eofed $ liftIO $ throwIO $ mkIOError eofErrorType "data" Nothing Nothing

readExact :: MonadIO m => Context -> Int -> m Bytes
readExact ctx sz = do
        hdrbs <- liftIO $ connectionRecv ctx sz
        when (B.length hdrbs < sz) $ do
                setEOF ctx
                if B.null hdrbs
                        then throwCore Error_EOF
                        else throwCore (Error_Packet ("partial packet: expecting " ++ show sz ++ " bytes, got: " ++ (show $B.length hdrbs)))
        return hdrbs

recvRecord :: MonadIO m => Context -> m (Either TLSError (Record Plaintext))
recvRecord ctx = readExact ctx 5 >>= either (return . Left) recvLength . decodeHeader
        where recvLength header@(Header _ _ readlen)
                | readlen > 16384 + 2048 = return $ Left $ Error_Protocol ("record exceeding maximum size", True, RecordOverflow)
                | otherwise              = do
                        content <- readExact ctx (fromIntegral readlen)
                        liftIO $ (loggingIORecv $ ctxLogging ctx) header content
                        usingState ctx $ disengageRecord $ rawToRecord header (fragmentCiphertext content)


-- | receive one packet from the context that contains 1 or
-- many messages (many only in case of handshake). if will returns a
-- TLSError if the packet is unexpected or malformed
recvPacket :: MonadIO m => Context -> m (Either TLSError Packet)
recvPacket ctx = do
        erecord <- recvRecord ctx
        case erecord of
                Left err     -> return $ Left err
                Right record -> do
                        pkt <- usingState ctx $ processPacket record
                        case pkt of
                                Right p -> liftIO $ (loggingPacketRecv $ ctxLogging ctx) $ show p
                                _       -> return ()
                        return pkt

recvPacketHandshake :: MonadIO m => Context -> m [Handshake]
recvPacketHandshake ctx = do
        pkts <- recvPacket ctx
        case pkts of
                Right (Handshake l) -> return l
                Right x             -> fail ("unexpected type received. expecting handshake and got: " ++ show x)
                Left err            -> throwCore err

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
                                         sendPacket ctx (Handshake [NextProtocolNegotiation proto])
                                         usingState_ ctx $ setNegotiatedProtocol proto
            -- client offered, server didn't pick up. do nothing.
            (Just _, Nothing) -> return ()
            -- client didn't offer. do nothing.
            (Nothing, _) -> return ()
        liftIO $ connectionFlush ctx
        cf <- usingState_ ctx $ getHandshakeDigest isClient
        sendPacket ctx (Handshake [Finished cf])
        liftIO $ connectionFlush ctx

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

-- | Send one packet to the context
sendPacket :: MonadIO m => Context -> Packet -> m ()
sendPacket ctx pkt = do
        liftIO $ (loggingPacketSent $ ctxLogging ctx) (show pkt)
        dataToSend <- usingState_ ctx $ writePacket pkt
        liftIO $ (loggingIOSent $ ctxLogging ctx) dataToSend
        liftIO $ connectionSend ctx dataToSend

-- | notify the context that this side wants to close connection.
-- this is important that it is called before closing the handle, otherwise
-- the session might not be resumable (for version < TLS1.2).
--
-- this doesn't actually close the handle
bye :: MonadIO m => Context -> m ()
bye ctx = sendPacket ctx $ Alert [(AlertLevel_Warning, CloseNotify)]

-- | If the Next Protocol Negotiation extension has been used, this will
-- return get the protocol agreed upon.
getNegotiatedProtocol :: MonadIO m => Context -> m (Maybe B.ByteString)
getNegotiatedProtocol ctx = usingState_ ctx S.getNegotiatedProtocol

-- | when a new handshake is done, wrap up & clean up.
handshakeTerminate :: MonadIO m => Context -> m ()
handshakeTerminate ctx = do
        session <- usingState_ ctx getSession
        -- only callback the session established if we have a session
        case session of
                Session (Just sessionId) -> do
                        sessionData <- usingState_ ctx getSessionData
                        liftIO $ (onSessionEstablished $ ctxParams ctx) sessionId (fromJust sessionData)
                _ -> return ()
        -- forget all handshake data now and reset bytes counters.
        usingState_ ctx endHandshake
        updateMeasure ctx resetBytesCounters
        -- mark the secure connection up and running.
        setEstablished ctx True
        return ()

-- client part of handshake. send a bunch of handshake of client
-- values intertwined with response from the server.
handshakeClient :: MonadIO m => Context -> m ()
handshakeClient ctx = do
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
                clientCerts  = map fst $ pCertificates params
                getExtensions = sequence [secureReneg, npnExtention] >>= return . catMaybes
                secureReneg  =
                        if pUseSecureRenegotiation params
                        then usingState_ ctx (getVerifiedData True) >>= \vd -> return $ Just (0xff01, encodeExtSecureRenegotiation vd Nothing)
                        else return Nothing
                npnExtention = if isJust $ onNPNServerSuggest params
                                 then return $ Just (13172, "")
                                 else return Nothing
                sendClientHello = do
                        crand <- getStateRNG ctx 32 >>= return . ClientRandom
                        let clientSession = Session . maybe Nothing (Just . fst) $ sessionResumeWith params
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

                sendCertificate = do
                        -- Send Certificate if requested. XXX disabled for now.
                        certRequested <- return False
                        when certRequested (sendPacket ctx $ Handshake [Certificates clientCerts])

                sendCertificateVerify =
                        {- maybe send certificateVerify -}
                        {- FIXME not implemented yet -}
                        return ()

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

                        let resumingSession = case sessionResumeWith params of
                                Just (sessionId, sessionData) -> if serverSession == Session (Just sessionId) then Just sessionData else Nothing
                                Nothing                       -> Nothing
                        usingState_ ctx $ setSession serverSession (isJust resumingSession)
                        usingState_ ctx $ processServerHello sh
                        case decodeExtNextProtocolNegotiation `fmap` (lookup 13172 exts) of
                          Just (Right protos) -> usingState_ ctx $ do
                                                   setExtensionNPN True
                                                   setServerNextProtocolSuggest protos
                          Just (Left err) -> throwCore (Error_Protocol ("could not decode NPN handshake: " ++ show err, True, DecodeError))
                          Nothing -> return ()
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
                        where
                                rejectOnException :: SomeException -> IO TLSCertificateUsage
                                rejectOnException e = return $ CertificateUsageReject $ CertificateRejectOther $ show e
                processCertificate p = processServerKeyExchange p

                processServerKeyExchange :: MonadIO m => Handshake -> m (RecvState m)
                processServerKeyExchange (ServerKeyXchg _) = return $ RecvStateHandshake processCertificateRequest
                processServerKeyExchange p                 = processCertificateRequest p

                processCertificateRequest (CertRequest _ _ _) = do
                        --modify (\sc -> sc { scCertRequested = True })
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

                -- on certificate reject, throw an exception with the proper protocol alert error.
                certificateRejected CertificateRejectRevoked =
                        throwCore $ Error_Protocol ("certificate is revoked", True, CertificateRevoked)
                certificateRejected CertificateRejectExpired =
                        throwCore $ Error_Protocol ("certificate has expired", True, CertificateExpired)
                certificateRejected CertificateRejectUnknownCA =
                        throwCore $ Error_Protocol ("certificate has unknown CA", True, UnknownCa)
                certificateRejected (CertificateRejectOther s) =
                        throwCore $ Error_Protocol ("certificate rejected: " ++ s, True, CertificateUnknown)

handshakeServerWith :: MonadIO m => Context -> Handshake -> m ()
handshakeServerWith ctx clientHello@(ClientHello ver _ clientSession ciphers compressions exts) = do
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
                (Session (Just clientSessionId)) -> liftIO $ onSessionResumption params $ clientSessionId
                (Session Nothing)                -> return Nothing
        case resumeSessionData of
                Nothing -> do
                        handshakeSendServerData
                        liftIO $ connectionFlush ctx

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
                clientRequestedNPN = isJust $ lookup 13172 exts

                ---
                recvClientData = runRecvState ctx (RecvStateHandshake processClientCertificate)

                processClientCertificate (Certificates _) = return $ RecvStateHandshake processClientKeyExchange
                processClientCertificate p = processClientKeyExchange p

                processClientKeyExchange (ClientKeyXchg _) = return $ RecvStateNext processCertificateVerify
                processClientKeyExchange p                 = unexpected (show p) (Just "client key exchange")

                processCertificateVerify (Handshake [CertVerify _]) = return $ RecvStateNext expectChangeCipher
                processCertificateVerify p = expectChangeCipher p

                expectChangeCipher ChangeCipherSpec = do npn <- usingState_ ctx getExtensionNPN
                                                         return $ RecvStateHandshake $ if npn
                                                                                         then expectNPN
                                                                                         else expectFinish
                expectChangeCipher p                = unexpected (show p) (Just "change cipher")

                expectNPN (NextProtocolNegotiation _) = return $ RecvStateHandshake expectFinish
                expectNPN p                           = unexpected (show p) (Just "Handshake NextProtocolNegotiation")

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
                                                return $ encodeExtSecureRenegotiation cvf (Just svf)
                                        return [ (0xff01, vf) ]
                                else return []
                        nextProtocols <-
                          if clientRequestedNPN
                            then liftIO $ onSuggestNextProtocols params
                            else return Nothing
                        npnExt <- case nextProtocols of
                                    Just protos -> do usingState_ ctx $ do setExtensionNPN True
                                                                           setServerNextProtocolSuggest protos
                                                      return [ (13172, encodeExtNextProtocolNegotiation protos) ]
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
                        when (pWantClientCert params) $ do
                                let certTypes = [ CertificateType_RSA_Sign ]
                                let creq = CertRequest certTypes Nothing [0,0,0]
                                sendPacket ctx (Handshake [creq])
                        -- Send HelloDone
                        sendPacket ctx (Handshake [ServerHelloDone])

handshakeServerWith _ _ = fail "unexpected handshake type received. expecting client hello"

-- after receiving a client hello, we need to redo a handshake
handshakeServer :: MonadIO m => Context -> m ()
handshakeServer ctx = do
        hss <- recvPacketHandshake ctx
        case hss of
                [ch] -> handshakeServerWith ctx ch
                _    -> fail ("unexpected handshake received, excepting client hello and received " ++ show hss)

-- | Handshake for a new TLS connection
-- This is to be called at the beginning of a connection, and during renegotiation
handshake :: MonadIO m => Context -> m ()
handshake ctx = do
        cc <- usingState_ ctx (stClientContext <$> get)
        liftIO $ handleException $ if cc then handshakeClient ctx else handshakeServer ctx
        where
                handleException f = catch f $ \exception -> do
                        let tlserror = maybe (Error_Misc $ show exception) id $ fromException exception
                        setEstablished ctx False
                        sendPacket ctx (errorToAlert tlserror)
                        handshakeFailed tlserror

-- | sendData sends a bunch of data.
-- It will automatically chunk data to acceptable packet size
sendData :: MonadIO m => Context -> L.ByteString -> m ()
sendData ctx dataToSend = checkValid ctx >> mapM_ sendDataChunk (L.toChunks dataToSend)
        where sendDataChunk d
                | B.length d > 16384 = do
                        let (sending, remain) = B.splitAt 16384 d
                        sendPacket ctx $ AppData sending
                        sendDataChunk remain
                | otherwise = sendPacket ctx $ AppData d

-- | recvData get data out of Data packet, and automatically renegotiate if
-- a Handshake ClientHello is received
recvData :: MonadIO m => Context -> m B.ByteString
recvData ctx = do
        checkValid ctx
        pkt <- recvPacket ctx
        case pkt of
                -- on server context receiving a client hello == renegotiation
                Right (Handshake [ch@(ClientHello {})]) ->
                        handshakeServerWith ctx ch >> recvData ctx
                -- on client context, receiving a hello request == renegotiation
                Right (Handshake [HelloRequest]) ->
                        handshakeClient ctx >> recvData ctx
                Right (Alert [(AlertLevel_Fatal, _)]) -> do
                        setEOF ctx
                        return B.empty
                Right (Alert [(AlertLevel_Warning, CloseNotify)]) -> do
                        setEOF ctx
                        return B.empty
                Right (AppData x) -> return x
                Right p           -> error ("error unexpected packet: " ++ show p)
                Left err          -> error ("error received: " ++ show err)

recvData' :: MonadIO m => Context -> m L.ByteString
recvData' ctx = recvData ctx >>= return . L.fromChunks . (:[])
