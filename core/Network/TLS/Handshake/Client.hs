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
    , postHandshakeAuthClientWith
    ) where

import Network.TLS.Crypto
import Network.TLS.Context.Internal
import Network.TLS.Parameters
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Credentials
import Network.TLS.Packet hiding (getExtensions)
import Network.TLS.ErrT
import Network.TLS.Extension
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.State
import Network.TLS.Measurement
import Network.TLS.Util (bytesEq, catchException, fromJust, mapChunks_)
import Network.TLS.Types
import Network.TLS.X509
import qualified Data.ByteString as B
import Data.X509 (ExtKeyUsageFlag(..))

import Control.Monad.State.Strict
import Control.Exception (SomeException, bracket)

import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.Certificate
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Random
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
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
handshakeClient' :: ClientParams -> Context -> [Group] -> Maybe (ClientRandom, Session, Version) -> IO ()
handshakeClient' cparams ctx groups mparams = do
    updateMeasure ctx incrementNbHandshakes
    (ClientHello _ crand clientSession _ _ exts _, rtt0) <- sendClientHello cparams ctx groups mparams
    let extIds = map (\(ExtensionRaw i _) -> i) exts
    recvServerHello clientSession extIds
    ver <- usingState_ ctx getVersion
    unless (maybe True (\(_, _, v) -> v == ver) mparams) $
        throwCore $ Error_Protocol ("version changed after hello retry", True, IllegalParameter)
    -- recvServerHello sets TLS13HRR according to the server random.
    -- For 1st server hello, getTLS13HR returns True if it is HRR and False otherwise.
    -- For 2nd server hello, getTLS13HR returns False since it is NOT HRR.
    hrr <- usingState_ ctx getTLS13HRR
    if ver == TLS13 then
        if hrr then do
            let mparams' = Just (crand, clientSession, ver)
            handleHRR (drop 1 groups) mparams'
          else do
            handshakeClient13 cparams ctx groupToSend
      else do
        when rtt0 $
            throwCore $ Error_Protocol ("server denied TLS 1.3 when connecting with early data", True, HandshakeFailure)
        sessionResuming <- usingState_ ctx isSessionResuming
        if sessionResuming
            then sendChangeCipherAndFinish ctx ClientRole
            else do sendClientData cparams ctx
                    sendChangeCipherAndFinish ctx ClientRole
                    recvChangeCipherAndFinish ctx
        handshakeTerminate ctx
  where groupToSend = listToMaybe groups
        recvServerHello clientSession sentExts = runRecvState ctx recvState
          where recvState = RecvStateNext $ \p ->
                    case p of
                        Handshake hs -> onRecvStateHandshake ctx (RecvStateHandshake $ onServerHello ctx cparams clientSession sentExts) hs -- this adds SH to hstHandshakeMessages
                        Alert a      ->
                            case a of
                                [(AlertLevel_Warning, UnrecognizedName)] ->
                                    if clientUseServerNameIndication cparams
                                        then return recvState
                                        else throwAlert a
                                _ -> throwAlert a
                        _ -> unexpected (show p) (Just "handshake")
                throwAlert a = usingState_ ctx $ throwError $ Error_Protocol ("expecting server hello, got alert : " ++ show a, True, HandshakeFailure)

        handleHRR [] _ = throwCore $ Error_Protocol ("group is exhausted in the client side", True, IllegalParameter)
        handleHRR groups' mparams' = do
            when (isJust mparams) $
                throwCore $ Error_Protocol ("server sent too many hello retries", True, UnexpectedMessage)
            mks <- usingState_ ctx getTLS13KeyShare
            case mks of
              Just (KeyShareHRR selectedGroup)
                | selectedGroup `elem` groups' -> do
                      usingHState ctx $ setTLS13HandshakeMode HelloRetryRequest
                      clearTxState ctx
                      let cparams' = cparams { clientEarlyData = Nothing }
                      runPacketFlight ctx $ sendChangeCipherSpec13 ctx
                      handshakeClient' cparams' ctx [selectedGroup] mparams'
                | otherwise -> throwCore $ Error_Protocol ("server-selected group is not supported", True, IllegalParameter)
              Just _  -> error "handshakeClient': invalid KeyShare value"
              Nothing -> throwCore $ Error_Protocol ("key exchange not implemented in HRR, expected key_share extension", True, HandshakeFailure)


makeClientHello :: ClientParams -> Context -> [Group] -> Maybe (ClientRandom, Session, Version) -> IO (Handshake, Maybe (CipherChoice, ByteString))
makeClientHello cparams ctx groups mparams = do
    (crand, clientSession) <- generateClientHelloParams
    let ver = if tls13 then TLS12 else highestVer
    hrr <- usingState_ ctx getTLS13HRR
    unless hrr $ startHandshake ctx ver crand
    usingState_ ctx $ setVersionIfUnset highestVer
    let cipherIds = map cipherID ciphers
        compIds = map compressionID compressions
        mkClientHello exts = ClientHello ver crand clientSession cipherIds compIds exts Nothing
    pskInfo <- getPskInfo
    let rtt0info = pskInfo >>= get0RTTinfo
        rtt0 = isJust rtt0info
    extensions0 <- catMaybes <$> getExtensions pskInfo rtt0
    extensions <- adjustExtentions pskInfo extensions0 $ mkClientHello extensions0
    let clientHello = mkClientHello extensions
    return (clientHello, rtt0info)
  where
    ciphers      = supportedCiphers $ ctxSupported ctx
    compressions = supportedCompressions $ ctxSupported ctx

    getExtensions pskInfo rtt0 = sequence
        [ sniExtension
        , secureReneg
        , alpnExtension
        , groupExtension
        , ecPointExtension
        --, sessionTicketExtension
        , signatureAlgExtension
        --, heartbeatExtension
        , versionExtension
        , earlyDataExtension rtt0
        , keyshareExtension
        , pskExchangeModeExtension
        , cookieExtension
        , postHandshakeAuthExtension
        , preSharedKeyExtension pskInfo -- MUST be last
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
            let vers = filter (>= TLS10) $ supportedVersions $ ctxSupported ctx
            return $ Just $ toExtensionRaw $ SupportedVersionsClientHello vers
      | otherwise = return Nothing

    -- FIXME
    keyshareExtension
      | tls13 = case groupToSend of
              Nothing  -> return Nothing
              Just grp -> do
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

    getPskInfo =
        case sessionAndCipherToResume13 of
            Nothing -> return Nothing
            Just (sid, sdata, sCipher) -> do
                let tinfo = fromJust "sessionTicketInfo" $ sessionTicketInfo sdata
                age <- getAge tinfo
                return $ if isAgeValid age tinfo
                    then Just (sid, sdata, makeCipherChoice TLS13 sCipher, ageToObfuscatedAge age tinfo)
                    else Nothing

    preSharedKeyExtension pskInfo =
        case pskInfo of
            Nothing -> return Nothing
            Just (sid, _, choice, obfAge) ->
                let zero = cZero choice
                    identity = PskIdentity sid obfAge
                    offeredPsks = PreSharedKeyClientHello [identity] [zero]
                 in return $ Just $ toExtensionRaw offeredPsks

    pskExchangeModeExtension
      | tls13     = return $ Just $ toExtensionRaw $ PskKeyExchangeModes [PSK_DHE_KE]
      | otherwise = return Nothing

    earlyDataExtension rtt0
      | rtt0 = return $ Just $ toExtensionRaw (EarlyDataIndication Nothing)
      | otherwise = return Nothing

    cookieExtension = do
        mcookie <- usingState_ ctx getTLS13Cookie
        case mcookie of
          Nothing     -> return Nothing
          Just cookie -> return $ Just $ toExtensionRaw cookie

    postHandshakeAuthExtension
      | tls13     = return $ Just $ toExtensionRaw PostHandshakeAuth
      | otherwise = return Nothing

    adjustExtentions pskInfo exts ch =
        case pskInfo of
            Nothing -> return exts
            Just (_, sdata, choice, _) -> do
                  let psk = sessionSecret sdata
                      earlySecret = initEarlySecret choice (Just psk)
                  usingHState ctx $ setTLS13EarlySecret earlySecret
                  let ech = encodeHandshake ch
                      h = cHash choice
                      siz = hashDigestSize h
                  binder <- makePSKBinder ctx earlySecret h (siz + 3) (Just ech)
                  let exts' = init exts ++ [adjust (last exts)]
                      adjust (ExtensionRaw eid withoutBinders) = ExtensionRaw eid withBinders
                        where
                          withBinders = replacePSKBinder withoutBinders binder
                  return exts'

    get0RTTinfo (_, sdata, choice, _) = do
        earlyData <- clientEarlyData cparams
        guard (B.length earlyData <= sessionMaxEarlyDataSize sdata)
        return (choice, earlyData)

    highestVer = maximum $ supportedVersions $ ctxSupported ctx
    tls13 = highestVer >= TLS13
    groupToSend = listToMaybe groups

    generateClientHelloParams =
        case mparams of
            -- Client random and session in the second client hello for
            -- retry must be the same as the first one.
            Just (crand, clientSession, _) -> return (crand, clientSession)
            Nothing -> do
                crand <- clientRandom ctx
                let paramSession = case clientWantSessionResume cparams of
                        Nothing -> Session Nothing
                        Just (sid, sdata)
                            | sessionVersion sdata >= TLS13 -> Session Nothing
                            | otherwise                     -> Session (Just sid)
                -- In compatibility mode a client not offering a pre-TLS 1.3
                -- session MUST generate a new 32-byte value
                if tls13 && paramSession == Session Nothing
                    then do
                        randomSession <- newSession ctx
                        return (crand, randomSession)
                    else return (crand, paramSession)

sendClientHello :: ClientParams -> Context -> [Group] -> Maybe (ClientRandom, Session, Version) -> IO (Handshake, Bool)
sendClientHello cparams ctx groups mparams = do
    (clientHello, rtt0info) <- makeClientHello cparams ctx groups mparams
    sendPacket ctx $ Handshake [clientHello]
    mapM_ send0RTT rtt0info
    let rtt0 = isJust rtt0info
    return (clientHello, rtt0)
  where
    send0RTT (choice, earlyData) = do
        let usedCipher = cCipher choice
            usedHash = cHash choice
        Just earlySecret <- usingHState ctx getTLS13EarlySecret
        -- Client hello is stored in hstHandshakeDigest
        -- But HandshakeDigestContext is not created yet.
        earlyKey <- calculateEarlySecret ctx choice (Right earlySecret) False
        let ClientTrafficSecret clientEarlySecret = pairClient earlyKey
        runPacketFlight ctx $ sendChangeCipherSpec13 ctx
        setTxState ctx usedHash usedCipher clientEarlySecret
        mapChunks_ 16384 (sendPacket13 ctx . AppData13) earlyData
        usingHState ctx $ setTLS13RTT0Status RTT0Sent


-- | Store the keypair and check that it is compatible with a list of
-- 'CertificateType' values.
storePrivInfoClient :: Context
                    -> [CertificateType]
                    -> Credential
                    -> IO ()
storePrivInfoClient ctx cTypes (cc, privkey) = do
    pubkey <- storePrivInfo ctx cc privkey
    unless (certificateCompatible pubkey cTypes) $
        throwCore $ Error_Protocol
            ( pubkeyType pubkey ++ " credential does not match allowed certificate types"
            , True
            , InternalError )

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
clientChain cparams ctx =
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
                Just cred@(cc, _)
                    -> do
                       let (cTypes, _, _) = cbdata
                       storePrivInfoClient ctx cTypes cred
                       return $ Just cc

-- | Return a most preferred 'HandAndSignatureAlgorithm' that is
-- compatible with the local key and server's signature
-- algorithms (both already saved).  Must only be called for TLS
-- versions 1.2 and up.
--
-- The values in the server's @signature_algorithms@ extension are
-- in descending order of preference.  However here the algorithms
-- are selected by client preference in @cHashSigs@.
--
getLocalHashSigAlg :: Context
                   -> [HashAndSignatureAlgorithm]
                   -> PubKey
                   -> IO HashAndSignatureAlgorithm
getLocalHashSigAlg ctx cHashSigs pubKey = do
    -- Must be present with TLS 1.2 and up.
    (Just (_, Just hashSigs, _)) <- usingHState ctx getCertReqCBdata
    let want = (&&) <$> signatureCompatible pubKey
                    <*> flip elem hashSigs
    case find want cHashSigs of
        Just best -> return best
        Nothing   -> throwCore $ Error_Protocol
                         ( keyerr pubKey
                         , True
                         , HandshakeFailure
                         )
  where
    keyerr k = "no " ++ pubkeyType k ++ " hash algorithm in common with the server"

-- | Return the supported 'CertificateType' values that are
-- compatible with at least one supported signature algorithm.
--
supportedCtypes :: [HashAndSignatureAlgorithm]
                -> [CertificateType]
supportedCtypes hashAlgs =
    nub $ foldr ctfilter [] hashAlgs
  where
    ctfilter x acc = case hashSigToCertType x of
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
                    unless (null certs) $
                        usingHState ctx $ setClientCertSent True
                    sendPacket ctx $ Handshake [Certificates cc]

        sendClientKeyXchg = do
            cipher <- usingHState ctx getPendingCipher
            ckx <- case cipherKeyExchange cipher of
                CipherKeyExchange_RSA -> do
                    clientVersion <- usingHState ctx $ gets hstClientVersion
                    (xver, prerand) <- usingState_ ctx $ (,) <$> getVersion <*> genRandom 46

                    let premaster = encodePreMasterSecret clientVersion prerand
                    masterSecret <- usingHState ctx $ setMasterSecretFromPre xver ClientRole premaster
                    logKey ctx (MasterSecret masterSecret)
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

                    unless (maybe False (isSupportedGroup ctx) ffGroup) $ do
                        groupUsage <- onCustomFFDHEGroup (clientHooks cparams) params srvpub `catchException`
                                          throwMiscErrorOnException "custom group callback failed"
                        case groupUsage of
                            GroupUsageInsecure           -> throwCore $ Error_Protocol ("FFDHE group is not secure enough", True, InsufficientSecurity)
                            GroupUsageUnsupported reason -> throwCore $ Error_Protocol ("unsupported FFDHE group: " ++ reason, True, HandshakeFailure)
                            GroupUsageInvalidPublic      -> throwCore $ Error_Protocol ("invalid server public key", True, IllegalParameter)
                            GroupUsageValid              -> return ()

                    -- When grp is known but not in the supported list we use it
                    -- anyway.  This provides additional validation and a more
                    -- efficient implementation.
                    (clientDHPub, premaster) <-
                        case ffGroup of
                             Nothing  -> do
                                 (clientDHPriv, clientDHPub) <- generateDHE ctx params
                                 let premaster = dhGetShared params clientDHPriv srvpub
                                 return (clientDHPub, premaster)
                             Just grp -> do
                                 usingHState ctx $ setNegotiatedGroup grp
                                 dhePair <- generateFFDHEShared ctx grp srvpub
                                 case dhePair of
                                     Nothing   -> throwCore $ Error_Protocol ("invalid server " ++ show grp ++ " public key", True, IllegalParameter)
                                     Just pair -> return pair

                    masterSecret <- usingHState ctx $ setMasterSecretFromPre xver ClientRole premaster
                    logKey ctx (MasterSecret masterSecret)
                    return $ CKX_DH clientDHPub

                getCKX_ECDHE = do
                    ServerECDHParams grp srvpub <- usingHState ctx getServerECDHParams
                    checkSupportedGroup ctx grp
                    usingHState ctx $ setNegotiatedGroup grp
                    ecdhePair <- generateECDHEShared ctx srvpub
                    case ecdhePair of
                        Nothing                  -> throwCore $ Error_Protocol ("invalid server " ++ show grp ++ " public key", True, IllegalParameter)
                        Just (clipub, premaster) -> do
                            xver <- usingState_ ctx getVersion
                            masterSecret <- usingHState ctx $ setMasterSecretFromPre xver ClientRole premaster
                            logKey ctx (MasterSecret masterSecret)
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
                pubKey      <- getLocalPublicKey ctx
                mhashSig    <- case ver of
                    TLS12 ->
                        let cHashSigs = supportedHashSignatures $ ctxSupported ctx
                         in Just <$> getLocalHashSigAlg ctx cHashSigs pubKey
                    _     -> return Nothing

                -- Fetch all handshake messages up to now.
                msgs   <- usingHState ctx $ B.concat <$> getHandshakeMessages
                sigDig <- createCertificateVerify ctx ver pubKey mhashSig msgs
                sendPacket ctx $ Handshake [CertVerify sigDig]

processServerExtension :: ExtensionRaw -> TLSSt ()
processServerExtension (ExtensionRaw extID content)
  | extID == extensionID_SecureRenegotiation = do
        cv <- getVerifiedData ClientRole
        sv <- getVerifiedData ServerRole
        let bs = extensionEncode (SecureRenegotiation cv $ Just sv)
        unless (bs `bytesEq` content) $ throwError $ Error_Protocol ("server secure renegotiation data not matching", True, HandshakeFailure)
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
onServerHello :: Context -> ClientParams -> Session -> [ExtensionID] -> Handshake -> IO (RecvState IO)
onServerHello ctx cparams clientSession sentExts (ServerHello rver serverRan serverSession cipher compression exts) = do
    when (rver == SSL2) $ throwCore $ Error_Protocol ("ssl2 is not supported", True, ProtocolVersion)
    -- find the compression and cipher methods that the server want to use.
    cipherAlg <- case find ((==) cipher . cipherID) (supportedCiphers $ ctxSupported ctx) of
                     Nothing  -> throwCore $ Error_Protocol ("server choose unknown cipher", True, IllegalParameter)
                     Just alg -> return alg
    compressAlg <- case find ((==) compression . compressionID) (supportedCompressions $ ctxSupported ctx) of
                       Nothing  -> throwCore $ Error_Protocol ("server choose unknown compression", True, IllegalParameter)
                       Just alg -> return alg

    -- intersect sent extensions in client and the received extensions from server.
    -- if server returns extensions that we didn't request, fail.
    let checkExt (ExtensionRaw i _)
          | i == extensionID_Cookie = False -- for HRR
          | otherwise               = i `notElem` sentExts
    when (any checkExt exts) $
        throwCore $ Error_Protocol ("spurious extensions received", True, UnsupportedExtension)

    let resumingSession =
            case clientWantSessionResume cparams of
                Just (sessionId, sessionData) -> if serverSession == Session (Just sessionId) then Just sessionData else Nothing
                Nothing                       -> Nothing
        isHRR = isHelloRetryRequest serverRan
    usingState_ ctx $ do
        setTLS13HRR isHRR
        setTLS13Cookie (guard isHRR >> extensionLookup extensionID_Cookie exts >>= extensionDecode MsgTServerHello)
        setSession serverSession (isJust resumingSession)
        setVersion rver -- must be before processing supportedVersions ext
        mapM_ processServerExtension exts

    setALPN ctx exts

    ver <- usingState_ ctx getVersion

    -- Some servers set TLS 1.2 as the legacy server hello version, and TLS 1.3
    -- in the supported_versions extension, *AND ALSO* set the TLS 1.2
    -- downgrade signal in the server random.  If we support TLS 1.3 and
    -- actually negotiate TLS 1.3, we must ignore the server random downgrade
    -- signal.  Therefore, 'isDowngraded' needs to take into account the
    -- negotiated version and the server random, as well as the list of
    -- client-side enabled protocol versions.
    --
    when (isDowngraded ver (supportedVersions $ clientSupported cparams) serverRan) $
        throwCore $ Error_Protocol ("version downgrade detected", True, IllegalParameter)

    case find (== ver) (supportedVersions $ ctxSupported ctx) of
        Nothing -> throwCore $ Error_Protocol ("server version " ++ show ver ++ " is not supported", True, ProtocolVersion)
        Just _  -> return ()
    if ver > TLS12 then do
        when (serverSession /= clientSession) $
            throwCore $ Error_Protocol ("received mismatched legacy session", True, IllegalParameter)
        established <- ctxEstablished ctx
        eof <- ctxEOF ctx
        when (established == Established && not eof) $
            throwCore $ Error_Protocol ("renegotiation to TLS 1.3 or later is not allowed", True, ProtocolVersion)
        ensureNullCompression compression
        failOnEitherError $ usingHState ctx $ setHelloParameters13 cipherAlg
        return RecvStateDone
      else do
        usingHState ctx $ setServerHelloParameters rver serverRan cipherAlg compressAlg
        case resumingSession of
            Nothing          -> return $ RecvStateHandshake (processCertificate cparams ctx)
            Just sessionData -> do
                let masterSecret = sessionSecret sessionData
                usingHState ctx $ setMasterSecret rver ClientRole masterSecret
                logKey ctx (MasterSecret masterSecret)
                return $ RecvStateNext expectChangeCipher
onServerHello _ _ _ _ p = unexpected (show p) (Just "server hello")

processCertificate :: ClientParams -> Context -> Handshake -> IO (RecvState IO)
processCertificate cparams ctx (Certificates certs) = do
    when (isNullCertificateChain certs) $
        throwCore $ Error_Protocol ("server certificate missing", True, DecodeError)
    -- run certificate recv hook
    ctxWithHooks ctx (`hookRecvCertificates` certs)
    -- then run certificate validation
    usage <- catchException (wrapCertificateChecks <$> checkCert) rejectOnException
    case usage of
        CertificateUsageAccept        -> checkLeafCertificateKeyUsage
        CertificateUsageReject reason -> certificateRejected reason
    return $ RecvStateHandshake (processServerKeyExchange ctx)
  where shared = clientShared cparams
        checkCert = onServerCertificate (clientHooks cparams) (sharedCAStore shared)
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
                (CipherKeyExchange_DHE_RSA, SKX_DHE_RSA dhparams signature) ->
                    doDHESignature dhparams signature KX_RSA
                (CipherKeyExchange_DHE_DSS, SKX_DHE_DSS dhparams signature) ->
                    doDHESignature dhparams signature KX_DSS
                (CipherKeyExchange_ECDHE_RSA, SKX_ECDHE_RSA ecdhparams signature) ->
                    doECDHESignature ecdhparams signature KX_RSA
                (CipherKeyExchange_ECDHE_ECDSA, SKX_ECDHE_ECDSA ecdhparams signature) ->
                    doECDHESignature ecdhparams signature KX_ECDSA
                (cke, SKX_Unparsed bytes) -> do
                    ver <- usingState_ ctx getVersion
                    case decodeReallyServerKeyXchgAlgorithmData ver cke bytes of
                        Left _        -> throwCore $ Error_Protocol ("unknown server key exchange received, expecting: " ++ show cke, True, HandshakeFailure)
                        Right realSkx -> processWithCipher cipher realSkx
                    -- we need to resolve the result. and recall processWithCipher ..
                (c,_)           -> throwCore $ Error_Protocol ("unknown server key exchange received, expecting: " ++ show c, True, HandshakeFailure)
        doDHESignature dhparams signature kxsAlg = do
            -- FF group selected by the server is verified when generating CKX
            publicKey <- getSignaturePublicKey kxsAlg
            verified <- digitallySignDHParamsVerify ctx dhparams publicKey signature
            unless verified $ decryptError ("bad " ++ pubkeyType publicKey ++ " signature for dhparams " ++ show dhparams)
            usingHState ctx $ setServerDHParams dhparams

        doECDHESignature ecdhparams signature kxsAlg = do
            -- EC group selected by the server is verified when generating CKX
            publicKey <- getSignaturePublicKey kxsAlg
            verified <- digitallySignECDHParamsVerify ctx ecdhparams publicKey signature
            unless verified $ decryptError ("bad " ++ pubkeyType publicKey ++ " signature for ecdhparams")
            usingHState ctx $ setServerECDHParams ecdhparams

        getSignaturePublicKey kxsAlg = do
            publicKey <- usingHState ctx getRemotePublicKey
            unless (isKeyExchangeSignatureKey kxsAlg publicKey) $
                throwCore $ Error_Protocol ("server public key algorithm is incompatible with " ++ show kxsAlg, True, HandshakeFailure)
            return publicKey

processServerKeyExchange ctx p = processCertificateRequest ctx p

processCertificateRequest :: Context -> Handshake -> IO (RecvState IO)
processCertificateRequest ctx (CertRequest cTypesSent sigAlgs dNames) = do
    ver <- usingState_ ctx getVersion
    when (ver == TLS12 && isNothing sigAlgs) $
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

handshakeClient13 :: ClientParams -> Context -> Maybe Group -> IO ()
handshakeClient13 cparams ctx groupSent = do
    choice <- makeCipherChoice TLS13 <$> usingHState ctx getPendingCipher
    handshakeClient13' cparams ctx groupSent choice

handshakeClient13' :: ClientParams -> Context -> Maybe Group -> CipherChoice -> IO ()
handshakeClient13' cparams ctx groupSent choice = do
    (_, hkey, resuming) <- switchToHandshakeSecret ctx choice groupSent
    let handshakeSecret = triBase hkey
        ClientTrafficSecret clientHandshakeSecret = triClient hkey
        ServerTrafficSecret serverHandshakeSecret = triServer hkey
    rtt0accepted <- runRecvHandshake13 $ do
        accepted <- recvHandshake13 ctx $ expectEncryptedExtensions ctx
        unless resuming $ recvHandshake13 ctx $ expectCertRequest cparams ctx
        recvHandshake13hash ctx $ expectFinished choice serverHandshakeSecret
        return accepted
    hChSf <- transcriptHash ctx
    runPacketFlight ctx $ sendChangeCipherSpec13 ctx
    when rtt0accepted $ sendPacket13 ctx (Handshake13 [EndOfEarlyData13])
    setTxState ctx usedHash usedCipher clientHandshakeSecret
    sendClientFlight13 cparams ctx usedHash clientHandshakeSecret
    appKey <- switchToApplicationSecret ctx choice handshakeSecret hChSf
    let applicationSecret = triBase appKey
    setResumptionSecret ctx choice applicationSecret
    handshakeTerminate13 ctx
  where
    usedCipher = cCipher choice
    usedHash   = cHash choice

processCertRequest13 :: MonadIO m => Context -> CertReqContext -> [ExtensionRaw] -> m ()
processCertRequest13 ctx token exts = do
    let hsextID = extensionID_SignatureAlgorithms
        -- caextID = extensionID_SignatureAlgorithmsCert
    dNames <- canames
    -- The @signature_algorithms@ extension is mandatory.
    hsAlgs <- extalgs hsextID unsighash
    cTypes <- case hsAlgs of
        Just as ->
            let validAs = filter isHashSignatureValid13 as
             in return $ sigAlgsToCertTypes ctx validAs
        Nothing -> throwCore $ Error_Protocol
                        ( "invalid certificate request"
                        , True
                        , HandshakeFailure )
    -- Unused:
    -- caAlgs <- extalgs caextID uncertsig
    usingHState ctx $ do
        setCertReqToken  $ Just token
        setCertReqCBdata $ Just (cTypes, hsAlgs, dNames)
        -- setCertReqSigAlgsCert caAlgs
  where
    canames = case extensionLookup
                   extensionID_CertificateAuthorities exts of
        Nothing   -> return []
        Just  ext -> case extensionDecode MsgTCertificateRequest ext of
                         Just (CertificateAuthorities names) -> return names
                         _ -> throwCore $ Error_Protocol
                                  ( "invalid certificate request"
                                  , True
                                  , HandshakeFailure )
    extalgs extID decons = case extensionLookup extID exts of
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

----------------------------------------------------------------

switchToHandshakeSecret :: Context -> CipherChoice -> Maybe Group -> IO (Cipher, SecretTriple HandshakeSecret, Bool)
switchToHandshakeSecret ctx choice groupSent  = do
    ensureRecvComplete ctx
    ecdhe <- calcSharedKey
    (earlySecret, resuming) <- makeEarlySecret
    handKey <- calculateHandshakeSecret ctx choice earlySecret ecdhe
    let ServerTrafficSecret serverHandshakeSecret = triServer handKey
    setRxState ctx usedHash usedCipher serverHandshakeSecret
    return (usedCipher, handKey, resuming)
  where
    usedCipher = cCipher choice
    usedHash   = cHash choice
    hashSize   = hashDigestSize usedHash
    calcSharedKey = do
        serverKeyShare <- do
            mks <- usingState_ ctx getTLS13KeyShare
            case mks of
              Just (KeyShareServerHello ks) -> return ks
              Just _                        -> error "calcSharedKey: invalid KeyShare value"
              Nothing                       -> throwCore $ Error_Protocol ("key exchange not implemented, expected key_share extension", True, HandshakeFailure)
        let grp = keyShareEntryGroup serverKeyShare
        unless (groupSent == Just grp) $
            throwCore $ Error_Protocol ("received incompatible group for (EC)DHE", True, IllegalParameter)
        usingHState ctx $ setNegotiatedGroup grp
        usingHState ctx getGroupPrivate >>= fromServerKeyShare serverKeyShare

    makeEarlySecret = do
         mEarlySecretPSK <- usingHState ctx getTLS13EarlySecret
         case mEarlySecretPSK of
           Nothing -> return (initEarlySecret choice Nothing, False)
           Just earlySecretPSK@(BaseSecret sec) -> do
               mSelectedIdentity <- usingState_ ctx getTLS13PreSharedKey
               case mSelectedIdentity of
                 Nothing                          ->
                     return (initEarlySecret choice Nothing, False)
                 Just (PreSharedKeyServerHello 0) -> do
                     unless (B.length sec == hashSize) $
                         throwCore $ Error_Protocol ("selected cipher is incompatible with selected PSK", True, IllegalParameter)
                     usingHState ctx $ setTLS13HandshakeMode PreSharedKey
                     return (earlySecretPSK, True)
                 Just _                           -> throwCore $ Error_Protocol ("selected identity out of range", True, IllegalParameter)

switchToApplicationSecret :: Context -> CipherChoice -> BaseSecret HandshakeSecret -> ByteString -> IO (SecretTriple ApplicationSecret)
switchToApplicationSecret ctx choice handshakeSecret hChSf = do
    ensureRecvComplete ctx
    appKey <- calculateApplicationSecret ctx choice handshakeSecret hChSf
    let ServerTrafficSecret serverApplicationSecret0 = triServer appKey
    let ClientTrafficSecret clientApplicationSecret0 = triClient appKey
    setTxState ctx usedHash usedCipher clientApplicationSecret0
    setRxState ctx usedHash usedCipher serverApplicationSecret0
    return appKey
  where
    usedCipher = cCipher choice
    usedHash   = cHash choice

expectEncryptedExtensions :: MonadIO m => Context -> Handshake13 -> m Bool
expectEncryptedExtensions ctx (EncryptedExtensions13 eexts) = do
    liftIO $ setALPN ctx eexts
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
expectEncryptedExtensions _ p = unexpected (show p) (Just "encrypted extensions")

expectCertRequest :: MonadIO m => ClientParams -> Context -> Handshake13 -> RecvHandshake13M m ()
expectCertRequest cparams ctx (CertRequest13 token exts) = do
    processCertRequest13 ctx token exts
    recvHandshake13 ctx $ expectCertAndVerify cparams ctx
expectCertRequest cparams ctx other = do
    usingHState ctx $ do
        setCertReqToken   Nothing
        setCertReqCBdata  Nothing
        -- setCertReqSigAlgsCert Nothing
    expectCertAndVerify cparams ctx other

expectCertAndVerify :: MonadIO m => ClientParams -> Context -> Handshake13 -> RecvHandshake13M m ()
expectCertAndVerify cparams ctx (Certificate13 _ cc _) = do
    _ <- liftIO $ processCertificate cparams ctx (Certificates cc)
    let pubkey = certPubKey $ getCertificate $ getCertificateChainLeaf cc
    checkDigitalSignatureKey pubkey
    usingHState ctx $ setPublicKey pubkey
    recvHandshake13hash ctx $ expectCertVerify ctx pubkey
expectCertAndVerify _ _ p = unexpected (show p) (Just "server certificate")

expectCertVerify :: MonadIO m => Context -> PubKey -> ByteString -> Handshake13 -> m ()
expectCertVerify ctx pubkey hChSc (CertVerify13 sigAlg sig) = do
    ok <- checkCertVerify ctx pubkey sigAlg sig hChSc
    unless ok $ decryptError "cannot verify CertificateVerify"
expectCertVerify _ _ _ p = unexpected (show p) (Just "certificate verify")

expectFinished :: MonadIO m => CipherChoice -> ByteString -> ByteString -> Handshake13 -> m ()
expectFinished choice baseKey hashValue (Finished13 verifyData) = do
    let usedHash = cHash choice
    checkFinished usedHash baseKey hashValue verifyData
expectFinished _ _ _ p = unexpected (show p) (Just "server finished")

setResumptionSecret :: Context -> CipherChoice -> BaseSecret ApplicationSecret -> IO ()
setResumptionSecret ctx choice applicationSecret = do
    resumptionSecret <- calculateResumptionSecret ctx choice applicationSecret
    usingHState ctx $ setTLS13ResumptionSecret resumptionSecret

----------------------------------------------------------------

sendClientFlight13 :: ClientParams -> Context -> Hash -> ByteString -> IO ()
sendClientFlight13 cparams ctx usedHash baseKey = do
    chain <- clientChain cparams ctx
    runPacketFlight ctx $ do
        case chain of
            Nothing -> return ()
            Just cc -> usingHState ctx getCertReqToken >>= sendClientData13 cc
        rawFinished <- makeFinished ctx usedHash baseKey
        loadPacket13 ctx $ Handshake13 [rawFinished]
  where
    sendClientData13 chain (Just token) = do
        let (CertificateChain certs) = chain
            certExts = replicate (length certs) []
            cHashSigs = filter isHashSignatureValid13 $ supportedHashSignatures $ ctxSupported ctx
        loadPacket13 ctx $ Handshake13 [Certificate13 token chain certExts]
        case certs of
            [] -> return ()
            _  -> do
                  hChSc      <- transcriptHash ctx
                  pubKey     <- getLocalPublicKey ctx
                  sigAlg     <- liftIO $ getLocalHashSigAlg ctx cHashSigs pubKey
                  vfy        <- makeCertVerify ctx pubKey sigAlg hChSc
                  loadPacket13 ctx $ Handshake13 [vfy]
    --
    sendClientData13 _ _ =
        throwCore $ Error_Protocol
            ( "missing TLS 1.3 certificate request context token"
            , True
            , InternalError
            )

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

postHandshakeAuthClientWith :: ClientParams -> Context -> Handshake13 -> IO ()
postHandshakeAuthClientWith cparams ctx h@(CertRequest13 certReqCtx exts) =
    bracket (saveHState ctx) (restoreHState ctx) $ \_ -> do
        processHandshake13 ctx h
        processCertRequest13 ctx certReqCtx exts
        (usedHash, _, applicationSecretN) <- getTxState ctx
        sendClientFlight13 cparams ctx usedHash applicationSecretN

postHandshakeAuthClientWith _ _ _ =
    throwCore $ Error_Protocol ("unexpected handshake message received in postHandshakeAuthClientWith", True, UnexpectedMessage)
