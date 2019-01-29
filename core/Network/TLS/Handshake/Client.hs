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
--    , makeClientHello13
--    , handleServerHello13
--    , makeClientFinished13
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
import Network.TLS.Packet13 (encodeHandshake13, decodeHandshakes13)
import Network.TLS.ErrT
import Network.TLS.Extension
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.State
import Network.TLS.Measurement
import Network.TLS.Util (bytesEq, catchException, fromJust, mapChunks_)
import Network.TLS.Types
import Network.TLS.X509
import Network.TLS.Sending13
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
import Network.TLS.Wire

handshakeClientWith :: ClientParams -> Context -> Handshake -> IO ()
handshakeClientWith cparams ctx HelloRequest = handshakeClient cparams ctx
handshakeClientWith _       _   _            = throwCore $ Error_Protocol ("unexpected handshake message received in handshakeClientWith", True, HandshakeFailure)

-- client part of handshake. send a bunch of handshake of client
-- values intertwined with response from the server.
handshakeClient :: ClientParams -> Context -> IO ()
handshakeClient cparams ctx = handshakeClient' cparams ctx groups Nothing
  where
    groupsSupported = supportedGroups (ctxSupported ctx)
    groups = case clientWantSessionResume cparams of
        Nothing         -> groupsSupported
        Just (_, sdata) -> case sessionGroup sdata of
            Nothing  -> [] -- TLS 1.2 or earlier
            Just grp -> grp : filter (/= grp) groupsSupported

-- https://tools.ietf.org/html/rfc8446#section-4.1.2 says:
-- "The client will also send a
--  ClientHello when the server has responded to its ClientHello with a
--  HelloRetryRequest.  In that case, the client MUST send the same
--  ClientHello without modification, except as follows:"
--
-- So, the ClientRandom in the first client hello is necessary.
handshakeClient' :: ClientParams -> Context -> [Group] -> Maybe ClientRandom -> IO ()
handshakeClient' cparams ctx groups mcrand = do
    updateMeasure ctx incrementNbHandshakes
    sentExts <- sendClientHello cparams ctx groups mcrand
    recvServerHello cparams ctx sentExts
    ver <- usingState_ ctx getVersion
    -- recvServerHello sets TLS13HRR according to the server random.
    -- For 1st server hello, getTLS13HR returns True if it is HRR and False otherwise.
    -- For 2nd server hello, getTLS13HR returns False since it is NOT HRR.
    hrr <- usingState_ ctx getTLS13HRR
    handshakeClient'' cparams ctx groups ver hrr

handshakeClient'' :: ClientParams -> Context -> [Group] -> Version -> Bool -> IO ()
handshakeClient'' cparams ctx groups ver hrr
  | ver < TLS13 = do
        sessionResuming <- usingState_ ctx isSessionResuming
        if sessionResuming then
            sendChangeCipherAndFinish ctx ClientRole
          else do
            sendClientData cparams ctx
            sendChangeCipherAndFinish ctx ClientRole
            recvChangeCipherAndFinish ctx
        handshakeTerminate ctx
  | otherwise =
        if hrr then
          handleHRR $ drop 1 groups
        else
          handshakeClient13 cparams ctx
  where
    handleHRR [] = throwCore $ Error_Protocol ("group is exhausted in the client side", True, IllegalParameter)
    handleHRR groups' = do
        mks <- usingState_ ctx getTLS13KeyShare
        case mks of
          Just (KeyShareHRR selectedGroup)
            | selectedGroup `elem` groups' -> do
                  usingHState ctx $ setTLS13HandshakeMode HelloRetryRequest
                  clearTxState ctx
                  let cparams' = cparams { clientEarlyData = Nothing }
                  crand <- usingHState ctx $ hstClientRandom <$> get
                  handshakeClient' cparams' ctx [selectedGroup] (Just crand)
            | otherwise -> throwCore $ Error_Protocol ("server-selected group is not supported", True, IllegalParameter)
          Just _  -> error "handshakeClient': invalid KeyShare value"
          Nothing -> throwCore $ Error_Protocol ("key exchange not implemented in HRR, expected key_share extension", True, HandshakeFailure)

sendClientHello :: ClientParams -> Context -> [Group] -> Maybe ClientRandom -> IO [ExtensionID]
sendClientHello cparams ctx groups mcrand = do
    (clientHello, ext) <- makeClientHello cparams ctx groups mcrand
    sendPacket ctx $ Handshake [clientHello]
    send0RTT
    return ext
  where
    ciphers = supportedCiphers $ ctxSupported ctx
    highestVer = maximum $ supportedVersions $ ctxSupported ctx
    tls13 = highestVer >= TLS13

    send0RTT = case check0RTT cparams ciphers tls13 of
        Nothing -> return ()
        Just (usedCipher, earlyData) -> do
            let choice = makeChoice TLS13 usedCipher
                usedHash = cHash choice
            earlySecret <- usingHState ctx getTLS13Secret
            -- Client hello is stored in hstHandshakeDigest
            -- But HandshakeDigestContext is not created yet.
            earlyKey <- calculateEarlySecret ctx choice (Right earlySecret) False
            let ClientEarlySecret clientEarlySecret = triClient earlyKey
            setTxState ctx usedHash usedCipher clientEarlySecret
            mapChunks_ 16384 (sendPacket13 ctx . AppData13) earlyData
            usingHState ctx $ setTLS13RTT0Status RTT0Sent

_makeClientHello13 :: ClientParams -> Context -> IO (ByteString, [ExtensionID])
_makeClientHello13 cparams ctx = do
    (ClientHello ver crand clientSession cipherIds _ exts Nothing, ext)
      <- makeClientHello cparams ctx groups Nothing
    let clientHello13 = ClientHello13 ver crand clientSession cipherIds exts
        bs = encodeHandshake13 clientHello13
    update13 ctx bs
    return (bs, ext)
  where
    groups = supportedGroups (ctxSupported ctx)

makeClientHello :: ClientParams -> Context -> [Group] -> Maybe ClientRandom -> IO (Handshake, [ExtensionID])
makeClientHello cparams ctx groups mcrand = do
    crand <- clientRandom ctx mcrand
    let ver = if tls13 then TLS12 else highestVer
    hrr <- usingState_ ctx getTLS13HRR
    unless hrr $ startHandshake ctx ver crand
    usingState_ ctx $ setVersionIfUnset highestVer
    let cipherIds = map cipherID ciphers
        compIds = map compressionID compressions
        mkClientHello exts = ClientHello ver crand clientSession cipherIds compIds exts Nothing
    extensions0 <- catMaybes <$> getExtensions
    extensions <- adjustExtentions extensions0 $ mkClientHello extensions0
    let clientHello = mkClientHello extensions
        ext = map (\(ExtensionRaw i _) -> i) extensions
    return (clientHello, ext)
  where
    ciphers      = supportedCiphers $ ctxSupported ctx
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
                             ,cookieExtension
                             ,preSharedKeyExtension
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

    pskExchangeModeExtension
      | tls13     = return $ Just $ toExtensionRaw $ PskKeyExchangeModes [PSK_DHE_KE]
      | otherwise = return Nothing

    earlyDataExtension = case check0RTT cparams ciphers tls13 of
        Nothing -> return Nothing
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

    preSharedKeyExtension =
        case sessionAndCipherToResume13 cparams ciphers tls13 of
            Nothing -> return Nothing
            Just (sid, sdata, sCipher) -> do
                  let zero = cZero $ makeChoice TLS13 sCipher
                      tinfo = fromJust "sessionTicketInfo" $ sessionTicketInfo sdata
                  age <- getAge tinfo
                  if isAgeValid age tinfo then do
                      let obfAge = ageToObfuscatedAge age tinfo
                      let identity = PskIdentity sid obfAge
                          offeredPsks = PreSharedKeyClientHello [identity] [zero]
                      return $ Just $ toExtensionRaw offeredPsks
                    else
                      return Nothing

    adjustExtentions exts ch =
        case sessionAndCipherToResume13 cparams ciphers tls13 of
            Nothing -> return exts
            Just (_, sdata, sCipher) -> do
                  -- PSK is available.
                  -- Client Hellow is not available. It's now being created.
                  -- So, ClientEarlySecret cannot be calculated here.
                  let choice = makeChoice TLS13 sCipher
                      psk = sessionSecret sdata
                      earlySecret = calcEarlySecret choice (Just psk)
                  usingHState ctx $ setTLS13Secret earlySecret
                  let ech = encodeHandshake ch
                      h = cHash choice
                      siz = hashDigestSize h
                  binder <- makePSKBinder ctx earlySecret h (siz + 3) (Just ech)
                  let exts' = init exts ++ [adjust (last exts)]
                      adjust (ExtensionRaw eid withoutBinders) = ExtensionRaw eid withBinders
                        where
                          withBinders = replacePSKBinder withoutBinders binder
                  return exts'

recvServerHello :: ClientParams -> Context -> [ExtensionID] -> IO ()
recvServerHello cparams ctx sentExts = runRecvState ctx recvState
  where
    recvState = RecvStateNext $ \p -> case p of
      Handshake hs -> onRecvStateHandshake ctx (RecvStateHandshake $ onServerHello ctx cparams sentExts) hs -- this adds SH to hstHandshakeMessages
      Alert a      -> case a of
        [(AlertLevel_Warning, UnrecognizedName)] ->
            if clientUseServerNameIndication cparams
            then return recvState
            else throwAlert a
        _ -> throwAlert a
      _ -> fail ("unexepected type received. expecting handshake and got: " ++ show p)
    throwAlert a = usingState_ ctx $ throwError $ Error_Protocol ("expecting server hello, got alert : " ++ show a, True, HandshakeFailure)

check0RTT :: ClientParams -> [Cipher] -> Bool -> Maybe (Cipher, ByteString)
check0RTT cparams ciphers tls13 = do
    (_, sdata, sCipher) <- sessionAndCipherToResume13 cparams ciphers tls13
    earlyData <- clientEarlyData cparams
    guard (B.length earlyData <= sessionMaxEarlyDataSize sdata)
    return (sCipher, earlyData)

sessionAndCipherToResume13 :: ClientParams -> [Cipher] -> Bool -> Maybe (SessionID, SessionData, Cipher)
sessionAndCipherToResume13 cparams ciphers tls13 = do
    guard tls13
    (sid, sdata) <- clientWantSessionResume cparams
    guard (sessionVersion sdata >= TLS13)
    sCipher <- find (\c -> cipherID c == sessionCipher sdata) ciphers
    return (sid, sdata, sCipher)

-- | Store the keypair and check that it is compatible with a list of
-- 'CertificateType' values.
storePrivInfoClient :: Context
                    -> [CertificateType]
                    -> Credential
                    -> IO ()
storePrivInfoClient ctx cTypes (cc, privkey) = do
    privalg <- storePrivInfo ctx cc privkey
    unless (certificateCompatible privalg cTypes) $
        throwCore $ Error_Protocol
            ( show privalg ++ " credential does not match allowed certificate types"
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
-- compatible with the private key and server's signature
-- algorithms (both already saved).  Must only be called for TLS
-- versions 1.2 and up.
--
-- The values in the server's @signature_algorithms@ extension are
-- in descending order of preference.  However here the algorithms
-- are selected by client preference in @cHashSigs@.
--
getLocalHashSigAlg :: Context
                   -> [HashAndSignatureAlgorithm]
                   -> DigitalSignatureAlg
                   -> IO HashAndSignatureAlgorithm
getLocalHashSigAlg ctx cHashSigs keyAlg = do
    -- Must be present with TLS 1.2 and up.
    (Just (_, Just hashSigs, _)) <- usingHState ctx getCertReqCBdata
    let want = (&&) <$> signatureCompatible keyAlg
                    <*> flip elem hashSigs
    case find want cHashSigs of
        Just best -> return best
        Nothing   -> throwCore $ Error_Protocol
                         ( keyerr keyAlg
                         , True
                         , HandshakeFailure
                         )
  where
    keyerr alg = "no " ++ show alg ++ " hash algorithm in common with the server"

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
                    logKey ctx (MasterSecret12 masterSecret)
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
                            GroupUsageInvalidPublic      -> throwCore $ Error_Protocol ("invalid server public key", True, HandshakeFailure)
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
                                     Nothing   -> throwCore $ Error_Protocol ("invalid server " ++ show grp ++ " public key", True, HandshakeFailure)
                                     Just pair -> return pair

                    masterSecret <- usingHState ctx $ setMasterSecretFromPre xver ClientRole premaster
                    logKey ctx (MasterSecret12 masterSecret)
                    return $ CKX_DH clientDHPub

                getCKX_ECDHE = do
                    ServerECDHParams grp srvpub <- usingHState ctx getServerECDHParams
                    checkSupportedGroup ctx grp
                    usingHState ctx $ setNegotiatedGroup grp
                    ecdhePair <- generateECDHEShared ctx srvpub
                    case ecdhePair of
                        Nothing                  -> throwCore $ Error_Protocol ("invalid server " ++ show grp ++ " public key", True, HandshakeFailure)
                        Just (clipub, premaster) -> do
                            xver <- usingState_ ctx getVersion
                            masterSecret <- usingHState ctx $ setMasterSecretFromPre xver ClientRole premaster
                            logKey ctx (MasterSecret12 masterSecret)
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
                keyAlg      <- getLocalDigitalSignatureAlg ctx
                mhashSig    <- case ver of
                    TLS12 ->
                        let cHashSigs = supportedHashSignatures $ ctxSupported ctx
                         in Just <$> getLocalHashSigAlg ctx cHashSigs keyAlg
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
        ensureNullCompression compression
        usingHState ctx $ setHelloParameters13 cipherAlg
        return RecvStateDone
      else do
        usingHState ctx $ setServerHelloParameters rver serverRan cipherAlg compressAlg
        case resumingSession of
            Nothing          -> return $ RecvStateHandshake (processCertificate cparams ctx)
            Just sessionData -> do
                let masterSecret = sessionSecret sessionData
                usingHState ctx $ setMasterSecret rver ClientRole masterSecret
                logKey ctx (MasterSecret12 masterSecret)
                return $ RecvStateNext expectChangeCipher
onServerHello _ _ _ p = unexpected (show p) (Just "server hello")

processCertificate :: ClientParams -> Context -> Handshake -> IO (RecvState IO)
processCertificate cparams ctx (Certificates certs) = do
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
            signatureType <- getSignatureType kxsAlg
            verified <- digitallySignDHParamsVerify ctx dhparams signatureType signature
            unless verified $ decryptError ("bad " ++ show signatureType ++ " signature for dhparams " ++ show dhparams)
            usingHState ctx $ setServerDHParams dhparams

        doECDHESignature ecdhparams signature kxsAlg = do
            -- EC group selected by the server is verified when generating CKX
            signatureType <- getSignatureType kxsAlg
            verified <- digitallySignECDHParamsVerify ctx ecdhparams signatureType signature
            unless verified $ decryptError ("bad " ++ show signatureType ++ " signature for ecdhparams")
            usingHState ctx $ setServerECDHParams ecdhparams

        getSignatureType kxsAlg = do
            publicKey <- usingHState ctx getRemotePublicKey
            case (kxsAlg, publicKey) of
                (KX_RSA,   PubKeyRSA     _) -> return DS_RSA
                (KX_DSS,   PubKeyDSA     _) -> return DS_DSS
                (KX_ECDSA, PubKeyEC      _) -> return DS_ECDSA
                (KX_ECDSA, PubKeyEd25519 _) -> return DS_Ed25519
                (KX_ECDSA, PubKeyEd448   _) -> return DS_Ed448
                _                           -> throwCore $ Error_Protocol ("server public key algorithm is incompatible with " ++ show kxsAlg, True, HandshakeFailure)

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

handshakeClient13 :: ClientParams -> Context -> IO ()
handshakeClient13 cparams ctx = do
    choice <- makeChoice TLS13 <$> usingHState ctx getPendingCipher
    handshakeClient13' cparams ctx choice

handshakeClient13' :: ClientParams -> Context -> Choice -> IO ()
handshakeClient13' cparams ctx choice = do
    (_, hkey, resuming) <- switchToHandshakeSecret ctx choice
    let handshakeSecret = triBase hkey
        ClientHandshakeSecret clientHandshakeSecret = triClient hkey
        ServerHandshakeSecret serverHandshakeSecret = triServer hkey
    rtt0accepted <- runRecvHandshake13 $ do
        accepted <- recvHandshake13 ctx $ expectEncryptedExtensions ctx
        unless resuming $ do
            recvHandshake13 ctx $ expectCertRequest ctx
            pubkey <- recvHandshake13 ctx $ expectCertificate cparams ctx
            recvHandshake13 ctx $ expectCertVerify ctx pubkey
        recvHandshake13 ctx $ expectFinished ctx choice serverHandshakeSecret
        return accepted
    hChSf <- transcriptHash ctx
    when rtt0accepted $ sendPacket13 ctx (Handshake13 [EndOfEarlyData13])
    setTxState ctx usedHash usedCipher clientHandshakeSecret
    chain <- clientChain cparams ctx
    runPacketFlight ctx $ do
        case chain of
            Nothing -> return ()
            Just cc -> usingHState ctx getCertReqToken >>= sendClientData13 cc
        rawFinished <- makeFinished ctx usedHash clientHandshakeSecret
        loadPacket13 ctx $ Handshake13 [rawFinished]
    appKey <- switchToTrafficSecret ctx choice handshakeSecret hChSf
    let applicationSecret = triBase appKey
    setResumptionSecret ctx choice applicationSecret
    setEstablished ctx Established
  where
    usedCipher = cCipher choice
    usedHash   = cHash choice

    sendClientData13 chain (Just token) = do
        let (CertificateChain certs) = chain
            certExts = replicate (length certs) []
            cHashSigs = filter isHashSignatureValid13 $ supportedHashSignatures $ ctxSupported ctx
        loadPacket13 ctx $ Handshake13 [Certificate13 token chain certExts]
        case certs of
            [] -> return ()
            _  -> do
                  hChSc      <- transcriptHash ctx
                  keyAlg     <- getLocalDigitalSignatureAlg ctx
                  sigAlg     <- liftIO $ getLocalHashSigAlg ctx cHashSigs keyAlg
                  vfy        <- makeCertVerify ctx keyAlg sigAlg hChSc
                  loadPacket13 ctx $ Handshake13 [vfy]
    --
    sendClientData13 _ _ =
        throwCore $ Error_Protocol
            ( "missing TLS 1.3 certificate request context token"
            , True
            , InternalError
            )

switchToTrafficSecret :: Context -> Choice -> Secret13 -> ByteString -> IO SecretTriple
switchToTrafficSecret ctx choice handshakeSecret hChSf = do
    appKey <- calculateTrafficSecret ctx choice handshakeSecret (Just hChSf)
    let ServerApplicationSecret0 serverApplicationSecret0 = triServer appKey
    let ClientApplicationSecret0 clientApplicationSecret0 = triClient appKey
    setTxState ctx usedHash usedCipher clientApplicationSecret0
    setRxState ctx usedHash usedCipher serverApplicationSecret0
    return appKey
  where
    usedCipher = cCipher choice
    usedHash = cHash choice

setResumptionSecret :: Context -> Choice -> Secret13 -> IO ()
setResumptionSecret ctx choice applicationSecret = do
    resumptionSecret <- calculateResumptionSecret ctx choice applicationSecret
    usingHState ctx $ setTLS13Secret resumptionSecret

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

expectCertRequest :: MonadIO m => Context -> Handshake13 -> RecvHandshake13M m ()
expectCertRequest ctx (CertRequest13 token exts) = do
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

expectCertRequest ctx other = do
    usingHState ctx $ do
        setCertReqToken   Nothing
        setCertReqCBdata  Nothing
        -- setCertReqSigAlgsCert Nothing
    pushbackHandshake13 other

expectCertificate :: MonadIO m => ClientParams -> Context -> Handshake13 -> RecvHandshake13M m PubKey
expectCertificate cparams ctx (Certificate13 _ cc@(CertificateChain certChain) _) = do
    _ <- liftIO $ processCertificate cparams ctx (Certificates cc)
    pubkey <- case certChain of
                [] -> throwCore $ Error_Protocol ("server certificate missing", True, HandshakeFailure)
                c:_ -> return $ certPubKey $ getCertificate c
    usingHState ctx $ setPublicKey pubkey
    return pubkey
expectCertificate _ _ p = unexpected (show p) (Just "server certificate")

expectCertVerify :: MonadIO m => Context -> PubKey -> Handshake13 ->  RecvHandshake13M m ()
expectCertVerify ctx pubkey (CertVerify13 sigAlg sig) = do
    hChSc <- transcriptHash ctx
    let keyAlg = fromJust "fromPubKey" (fromPubKey pubkey)
    ok <- checkCertVerify ctx keyAlg sigAlg sig hChSc
    unless ok $ decryptError "cannot verify CertificateVerify"
expectCertVerify _ _ p = unexpected (show p) (Just "certificate verify")

expectFinished :: MonadIO m => Context -> Choice -> ByteString -> Handshake13 -> RecvHandshake13M m ()
expectFinished ctx choice serverHandshakeSecret (Finished13 verifyData) = do
    hChSv <- transcriptHash ctx
    let verifyData' = makeVerifyData usedHash serverHandshakeSecret hChSv
    when (verifyData' /= verifyData) $ decryptError "cannot verify finished"
  where
    usedHash = cHash choice
expectFinished _ _ _ p = unexpected (show p) (Just "server finished")


switchToHandshakeSecret :: Context -> Choice -> IO (Cipher, SecretTriple, Bool)
switchToHandshakeSecret ctx choice = do
    ecdhe <- calcSharedKey
    (earlySecret, resuming) <- makeEarlySecret
    handKey <- calculateHandshakeSecret ctx choice earlySecret ecdhe
    let ServerHandshakeSecret serverHandshakeSecret = triServer handKey
    setRxState ctx usedHash usedCipher serverHandshakeSecret
    return (usedCipher, handKey, resuming)
  where
    usedCipher = cCipher choice
    usedHash   = cHash choice

    -- The server may reject resuming.
    -- In this case, EarlySecret must be based on "zero".
    makeEarlySecret = do
        secret <- usingHState ctx getTLS13Secret
        case secret of
          earlySecretPSK@(EarlySecret _) -> do
              mSelectedIdentity <- usingState_ ctx getTLS13PreSharedKey
              case mSelectedIdentity of
                Nothing                          ->
                    return (calcEarlySecret choice Nothing, False)
                Just (PreSharedKeyServerHello 0) -> do
                    usingHState ctx $ setTLS13HandshakeMode PreSharedKey
                    return (earlySecretPSK, True)
                Just _                           -> throwCore $ Error_Protocol ("selected identity out of range", True, IllegalParameter)
          _ -> return (calcEarlySecret choice Nothing, False)
    calcSharedKey = do
        serverKeyShare <- do
            mks <- usingState_ ctx getTLS13KeyShare
            case mks of
              Just (KeyShareServerHello ks) -> return ks
              Just _                        -> error "calcSharedKey: invalid KeyShare value"
              Nothing                       -> throwCore $ Error_Protocol ("key exchange not implemented, expected key_share extension", True, HandshakeFailure)
        let grp = keyShareEntryGroup serverKeyShare
        checkSupportedGroup ctx grp
        usingHState ctx $ setNegotiatedGroup grp
        usingHState ctx getGroupPrivate >>= fromServerKeyShare serverKeyShare

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

-- | The third argument is server hello.
--   Returning handshake keys.
_handleServerHello13 :: ClientParams -> Context -> ByteString -> [ExtensionID] -> IO (Cipher, SecretTriple, Bool)
_handleServerHello13 cparams ctx bs sentExts = do
    let Right [ServerHello13 srand session cipher exts] = decodeHandshakes13 bs
        sh = ServerHello TLS12 srand session cipher 0 exts
    _ <- onServerHello ctx cparams sentExts sh
    update13 ctx bs
    choice <- makeChoice TLS13 <$> usingHState ctx getPendingCipher
    switchToHandshakeSecret ctx choice

-- | The third argument is handshake messages from encrypted extensions
--   to server finish.
--   Returning client finished and application keys.
_makeClientFinished13 :: ClientParams -> Context -> ByteString
                     -> SecretTriple -> Bool
                     -> IO (ByteString, SecretTriple)
_makeClientFinished13 cparams ctx bs handKey resuming = do
    choice <- makeChoice TLS13 <$> usingHState ctx getPendingCipher
    makeClientFinished' cparams ctx choice bs handKey resuming

makeClientFinished' :: ClientParams -> Context -> Choice -> ByteString -> SecretTriple -> Bool -> IO (ByteString, SecretTriple)
makeClientFinished' cparams ctx choice bs handKey resuming = do
    let Right hss = decodeHandshakes13 bs
    _rtt0accepted <- runRecvHandshake13' hss $ do
        accepted <- recvHandshake13' ctx $ expectEncryptedExtensions ctx
        unless resuming $ do
            recvHandshake13' ctx $ expectCertRequest ctx
            pubkey <- recvHandshake13' ctx $ expectCertificate cparams ctx
            recvHandshake13' ctx $ expectCertVerify ctx pubkey
        recvHandshake13' ctx $ expectFinished ctx choice serverHandshakeSecret
        return accepted
    hChSf <- transcriptHash ctx
    cf <- encodeHandshake13 <$> makeFinished ctx usedHash clientHandshakeSecret
    appKey <- switchToTrafficSecret ctx choice handshakeSecret hChSf
    let applicationSecret = triBase appKey
    setResumptionSecret ctx choice applicationSecret
    setEstablished ctx Established
    return (cf, appKey)
  where
    handshakeSecret = triBase handKey
    ServerHandshakeSecret serverHandshakeSecret = triServer handKey
    ClientHandshakeSecret clientHandshakeSecret = triClient handKey
    usedHash = cHash choice
