{-# LANGUAGE LambdaCase #-}
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
              Nothing         -> groupsSupported
              Just (_, sdata) -> case sessionGroup sdata of
                  Nothing  -> [] -- TLS 1.2 or earlier
                  Just grp -> grp : filter (/= grp) groupsSupported
        groupsSupported = supportedGroups (ctxSupported ctx)
    handshakeClient' cparams ctx groups Nothing

-- https://tools.ietf.org/html/rfc8446#section-4.1.2 says:
-- "The client will also send a
--  ClientHello when the server has responded to its ClientHello with a
--  HelloRetryRequest.  In that case, the client MUST send the same
--  ClientHello without modification, except as follows:"
--
-- So, the ClientRandom in the first client hello is necessary.
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
            crand <- clientRandom ctx mcr
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
                sendPacket13 ctx $ AppData13 earlyData
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

-- | When the server requests a client certificate, we try to
-- obtain a suitable certificate chain and private key via the
-- callback in the client parameters.  It is OK for the callback
-- to return an empty chain, in many cases the client certificate
-- is optional.  If the client wishes to abort the handshake for
-- lack of a suitable certificate, it can throw an exception in
-- the callback.
--
-- The return value is 'Nothing' when no @CertificateRequest@ was
-- received and no @Certificate@ message needs to be sent. An empty
-- chain means that an empty @Certificate@ message needs to be sent
-- to the server, naturally without a @CertificateVerify@.  A non-empty
-- 'CertificateChain' is the chain to send to the server along with
-- a corresponding 'CertificateVerify'.
--
-- With TLS < 1.2 the server's @CertificateRequest@ does not carry
-- a signature algorithm list.  It has a list of supported public
-- key signing algorithms in the @certificate_types@ field.  The
-- hash is implicit.  It is 'SHA1' for DSS and 'SHA1_MD5' for RSA.
--
-- With TLS == 1.2 the server's @CertificateRequest@ always has a
-- @supported_signature_algorithms@ list, as a fixed component of
-- the structure.  This list is (wrongly) overloaded to also limit
-- X.509 signatures in the client's certificate chain.  The BCP
-- strategy is to find a compatible chain if possible, but else
-- ignore the constraint, and let the server verify the chain as it
-- sees fit.  The @supported_signature_algorithms@ field is only
-- obligatory with respect to signatures on TLS messages, in this
-- case the @CertificateVerify@ message.  The @certificate_types@
-- field is still included.
--
-- With TLS 1.3 the server's @CertificateRequest@ has a mandatory
-- @signature_algorithms@ extension, the @signature_algorithms_cert@
-- extension, which is optional, carries a list of algorithms the
-- server promises to support in verifying the certificate chain.
-- As with TLS 1.2, the client's makes a /best-effort/ to deliver
-- a compatible certificate chain where all the CA signatures are
-- known to be supported, but it should not abort the connection
-- just because the chain might not work out, just send the best
-- chain you have and let the server worry about the rest.  The
-- supported public key algorithms are now inferred from the
-- @signature_algorithms@ extension and @certificate_types@ is
-- gone.
--
-- With TLS 1.3, we synthesize and store a @certificate_types@
-- field at the time that the server's @CertificateRequest@
-- message is received.  This is then present across all the
-- protocol versions, and can be used to determine whether
-- a @CertificateRequest@ was received or not.
--
-- If @signature_algorithms@ is 'Nothing', then we're doing
-- TLS 1.0 or 1.1.  The @signature_algorithms_cert@ extension
-- is optional in TLS 1.3, and so the application callback
-- will not be able to distinguish between TLS 1.[01] and
-- TLS 1.3 with no certificate algorithm hints, but this
-- just simplifies the chain selection process, all CA
-- signatures are OK.
--
clientChain :: ClientParams -> Context -> IO (Maybe CertificateChain)
clientChain cparams ctx = do
    usingHState ctx getCertReqCBdata >>= \case
        Nothing     -> return Nothing
        Just cbdata -> do
            let callback = onCertificateRequest $ clientHooks cparams
            chain <- liftIO $ callback cbdata `catchException`
                throwMiscErrorOnException "certificate request callback failed"
            case chain of
                Nothing
                    -> return $ Just $ CertificateChain []
                Just (CertificateChain [], _)
                    -> return $ Just $ CertificateChain []
                Just (cc, privkey)
                    -> do
                       let (cTypes, _, _) = cbdata
                       storePrivInfo ctx (Just cTypes) cc privkey
                       return $ Just cc

-- | Return a most preferred 'HandAndSignatureAlgorithm' that is
-- compatible with the private key and server's signature
-- algorithms (both already saved).  Must only be called for TLS
-- versions 1.2 and up.
--
-- The values in the server's @signature_algorithms@ extension are
-- in descending order of preference.  However here the algorithms
-- are selected by client preference in 'supportedHashSignatures'.
--
getLocalHashSigAlg :: Context
                   -> DigitalSignatureAlg
                   -> IO HashAndSignatureAlgorithm
getLocalHashSigAlg ctx keyAlg = do
    -- Must be present with TLS 1.2 and up.
    (Just (_, Just hashSigs, _)) <- usingHState ctx getCertReqCBdata
    let want = (&&) <$> signatureCompatible keyAlg
                    <*> flip elem hashSigs
    case find want $ supportedHashSignatures $ ctxSupported ctx of
        Just best -> return best
        Nothing   -> throwCore $ Error_Protocol
                         ( keyerr $ show keyAlg
                         , True
                         , HandshakeFailure
                         )
  where
    keyerr alg = "no " ++ alg ++ " hash algorithm in common with the server"

-- | Return the supported 'CertificateType' values that are
-- compatible with at least one supported signature algorithm.
--
supportedCtypes :: [HashAndSignatureAlgorithm]
                -> [CertificateType]
supportedCtypes hashAlgs =
    nub $ foldr ctfilter [] hashAlgs
  where
    ctfilter x acc = case hashSigToCertType13 x of
       Just cType | cType <= lastSupportedCertificateType
                 -> cType : acc
       _         -> acc
--
clientSupportedCtypes :: Context
                      -> [CertificateType]
clientSupportedCtypes ctx =
    supportedCtypes $ supportedHashSignatures $ ctxSupported ctx
--
sigAlgsToCertTypes :: Context
                   -> [HashAndSignatureAlgorithm]
                   -> [CertificateType]
sigAlgsToCertTypes ctx hashSigs =
    filter (`elem` supportedCtypes hashSigs) $ clientSupportedCtypes ctx

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
                Nothing                    -> return ()
                Just cc@(CertificateChain certs) -> do
                    when (not $ null certs) $
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
            ver <- usingState_ ctx getVersion

            -- Only send a certificate verify message when we
            -- have sent a non-empty list of certificates.
            --
            certSent <- usingHState ctx getClientCertSent
            when certSent $ do
                (_, keyAlg) <- usingHState ctx getLocalPrivateKey
                mhashSig    <- case ver of
                    TLS12 -> Just <$> getLocalHashSigAlg ctx keyAlg
                    _     -> return Nothing

                -- Fetch all handshake messages up to now.
                msgs   <- usingHState ctx $ B.concat <$> getHandshakeMessages
                sigDig <- createCertificateVerify ctx ver keyAlg mhashSig msgs
                sendPacket ctx $ Handshake [CertVerify sigDig]

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
    when (isDowngraded (supportedVersions $ clientSupported cparams) serverRan) $
        throwCore $ Error_Protocol ("verion downgrade detected", True, IllegalParameter)
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
        isHRR = isHelloRetryRequest serverRan
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
        usingHState ctx $ setHelloParameters13 cipherAlg
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
processCertificateRequest ctx (CertRequest cTypesSent sigAlgs dNames) = do
    ver <- usingState_ ctx getVersion
    when (ver == TLS12 && sigAlgs == Nothing) $
        throwCore $ Error_Protocol
            ( "missing TLS 1.2 certificate request signature algorithms"
            , True
            , InternalError
            )
    let cTypes = filter (<= lastSupportedCertificateType) cTypesSent
    usingHState ctx $ setCertReqCBdata $ Just (cTypes, sigAlgs, dNames)
    return $ RecvStateHandshake (processServerHelloDone ctx)
processCertificateRequest ctx p = do
    usingHState ctx $ setCertReqCBdata Nothing
    processServerHelloDone ctx p

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
    when rtt0accepted $ sendPacket13 ctx (Handshake13 [EndOfEarlyData13])
    -- putStrLn "---- setTxState ctx usedHash usedCipher clientHandshakeTrafficSecret"
    setTxState ctx usedHash usedCipher clientHandshakeTrafficSecret
    chain <- clientChain cparams ctx
    runPacketFlight ctx $ do
        case chain of
            Nothing -> return ()
            Just cc -> usingHState ctx getCertReqToken >>= sendClientData13 cc
        rawFinished <- makeFinished ctx usedHash clientHandshakeTrafficSecret
        loadPacket13 ctx $ Handshake13 [rawFinished]
    masterSecret <- switchToTrafficSecret handshakeSecret hChSf
    setResumptionSecret masterSecret
    setEstablished ctx Established
  where
    hashSize = hashDigestSize usedHash
    zero = B.replicate hashSize 0

    sendClientData13 chain (Just token) = do
        let (CertificateChain certs) = chain
            certExts = replicate (length certs) []
        loadPacket13 ctx $ Handshake13 [Certificate13 token chain certExts]
        case certs of
            [] -> return ()
            _  -> do
                  hChSc      <- transcriptHash ctx
                  (salg, pk) <- getSigKey
                  vfy        <- makeClientCertVerify ctx salg pk hChSc
                  loadPacket13 ctx $ Handshake13 [vfy]
      where
        getSigKey = do
            (privkey, privalg) <- usingHState ctx getLocalPrivateKey
            sigAlg <- liftIO $ getLocalHashSigAlg ctx privalg
            return (sigAlg, privkey)
    --
    sendClientData13 _ _ =
        throwCore $ Error_Protocol
            ( "missing TLS 1.3 certificate request context token"
            , True
            , InternalError
            )

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
        EncryptedExtensions13 eexts <- recvHandshake13 ctx
        setALPN ctx eexts
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
        hmsg <- recvHandshake13 ctx
        cert <- case hmsg of
            CertRequest13 token exts -> do
                let hsextID = extensionID_SignatureAlgorithms
                    -- caextID = extensionID_SignatureAlgorithmsCert
                dNames <- canames exts
                -- The @signature_algorithms@ extension is mandatory.
                hsAlgs <- extalgs hsextID exts unsighash
                cTypes <- case hsAlgs of
                    Just as -> return $ sigAlgsToCertTypes ctx as
                    Nothing -> throwCore $ Error_Protocol
                                   ( "invalid certificate request"
                                   , True
                                   , HandshakeFailure )
                -- Unused:
                -- caAlgs <- extalgs caextID exts uncertsig
                usingHState ctx $ do
                    setCertReqToken  $ Just token
                    setCertReqCBdata $ Just (cTypes, hsAlgs, dNames)
                    -- setCertReqSigAlgsCert caAlgs
                recvHandshake13 ctx
            _ -> do
                usingHState ctx $ do
                    setCertReqToken   Nothing
                    setCertReqCBdata  Nothing
                    -- setCertReqSigAlgsCert Nothing
                return hmsg

        -- FIXME: What happens when the pattern match fails?
        --
        let Certificate13 _ cc@(CertificateChain certChain) _ = cert
        _ <- processCertificate cparams ctx (Certificates cc)
        pubkey <- case certChain of
                    [] -> throwCore $ Error_Protocol ("server certificate missing", True, HandshakeFailure)
                    c:_ -> return $ certPubKey $ getCertificate c
        hChSc <- transcriptHash ctx
        CertVerify13 ss sig <- recvHandshake13 ctx
        checkServerCertVerify ss sig pubkey hChSc
      where
        canames exts = case extensionLookup
                            extensionID_CertificateAuthorities exts of
            Nothing   -> return []
            Just  ext -> case extensionDecode MsgTCertificateRequest ext of
                             Just (CertificateAuthorities names) -> return names
                             _ -> throwCore $ Error_Protocol
                                      ( "invalid certificate request"
                                      , True
                                      , HandshakeFailure )
        extalgs extID exts decons = case extensionLookup extID exts of
            Nothing   -> return Nothing
            Just  ext -> case extensionDecode MsgTCertificateRequest ext of
                             Just e
                               -> return    $ decons e
                             _ -> throwCore $ Error_Protocol
                                      ( "invalid certificate request"
                                      , True
                                      , HandshakeFailure )

        unsighash :: SignatureAlgorithms
                  -> Maybe [HashAndSignatureAlgorithm]
        unsighash (SignatureAlgorithms a) = Just a

        {- Unused for now
        uncertsig :: SignatureAlgorithmsCert
                  -> Maybe [HashAndSignatureAlgorithm]
        uncertsig (SignatureAlgorithmsCert a) = Just a
        -}

    recvFinished serverHandshakeTrafficSecret = do
        hChSv <- transcriptHash ctx
        let verifyData' = makeVerifyData usedHash serverHandshakeTrafficSecret hChSv
        Finished13 verifyData <- recvHandshake13 ctx
        when (verifyData' /= verifyData) $
            throwCore $ Error_Protocol ("cannot verify finished", True, HandshakeFailure)

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
                Right (Handshake13 (h:hs)) -> found h hs
                Right ChangeCipherSpec13   -> recvHandshake13 ctx
                Right x                    -> unexpected (show x) (Just "Handshake13")
                Left err                   -> throwCore err
        h:hs -> found h hs
  where
    found h hs = do usingHState ctx $ setTLS13HandshakeMsgs hs
                    updateHandshake13 ctx h >> return h

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
