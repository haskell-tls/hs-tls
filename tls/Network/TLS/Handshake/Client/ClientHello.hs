{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.TLS.Handshake.Client.ClientHello (
    sendClientHello,
    getPreSharedKeyInfo,
) where

import qualified Control.Exception as E
import Crypto.HPKE
import qualified Data.ByteString as B
import Network.TLS.ECH.Config

import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Client.Common
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Control
import Network.TLS.Handshake.Random
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.Handshake.TranscriptHash
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.Packet hiding (getExtensions)
import Network.TLS.Parameters
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Types

----------------------------------------------------------------

sendClientHello
    :: ClientParams
    -> Context
    -> [Group]
    -> Maybe (ClientRandom, Session, Version)
    -> PreSharedKeyInfo
    -> IO ClientRandom
sendClientHello cparams ctx groups mparams pskinfo = do
    crand <- generateClientHelloParams mparams -- Inner for ECH
    let nhpks = supportedHPKE $ ctxSupported ctx
        echcnfs = sharedECHConfig $ ctxShared ctx
        mEchParams = lookupECHConfigList nhpks echcnfs
    sendClientHello' cparams ctx groups crand pskinfo mEchParams
    return crand
  where
    highestVer = maximum $ supportedVersions $ ctxSupported ctx
    tls13 = highestVer >= TLS13
    ems = supportedExtendedMainSecret $ ctxSupported ctx

    -- Client random and session in the second client hello for
    -- retry must be the same as the first one.
    generateClientHelloParams (Just (crand, clientSession, _)) = do
        modifyTLS13State ctx $ \st -> st{tls13stSession = clientSession}
        return crand
    generateClientHelloParams Nothing = do
        crand <- clientRandom ctx
        let paramSession = case clientSessions cparams of
                [] -> Session Nothing
                (sidOrTkt, sdata) : _
                    | sessionVersion sdata >= TLS13 -> Session Nothing
                    | ems == RequireEMS && noSessionEMS -> Session Nothing
                    | isTicket sidOrTkt -> Session $ Just $ toSessionID sidOrTkt
                    | otherwise -> Session (Just sidOrTkt)
                  where
                    noSessionEMS = SessionEMS `notElem` sessionFlags sdata
        -- In compatibility mode a client not offering a pre-TLS 1.3
        -- session MUST generate a new 32-byte value
        if tls13 && paramSession == Session Nothing && not (ctxQUICMode ctx)
            then do
                randomSession <- newSession ctx
                modifyTLS13State ctx $ \st -> st{tls13stSession = randomSession}
                return crand
            else do
                modifyTLS13State ctx $ \st -> st{tls13stSession = paramSession}
                return crand

----------------------------------------------------------------

sendClientHello'
    :: ClientParams
    -> Context
    -> [Group]
    -> ClientRandom
    -> ( Maybe ([ByteString], SessionData, CipherChoice, Word32)
       , Maybe CipherChoice
       , Bool
       )
    -> Maybe (KDF_ID, AEAD_ID, ECHConfig)
    -> IO ()
sendClientHello' cparams ctx groups crand (pskInfo, rtt0info, rtt0) mEchParams = do
    let ver = if tls13 then TLS12 else highestVer
    clientSession <- tls13stSession <$> getTLS13State ctx
    hrr <- usingState_ ctx getTLS13HRR
    unless hrr $ startHandshake ctx ver crand
    usingState_ ctx $ setVersionIfUnset highestVer
    let cipherIds = map (CipherId . cipherID) ciphers
        compIds = map compressionID compressions
        mkClientHello exts = ClientHello ver crand compIds $ CHP clientSession cipherIds exts
    setMyRecordLimit ctx $ limitRecordSize $ sharedLimit $ ctxShared ctx
    extensions0 <- catMaybes <$> getExtensions
    let extensions1 = sharedHelloExtensions (clientShared cparams) ++ extensions0
    extensions <- adjustPreSharedKeyExt extensions1 $ mkClientHello extensions1
    let ch0 = mkClientHello extensions
    usingHState ctx $ setClientHello ch0
    updateTranscriptHashI ctx "ClientHelloI" $ encodeHandshake ch0
    ch <- case mEchParams of
        Nothing -> return ch0
        Just echParams -> do
            mcrandO <- usingHState ctx getOuterClientRandom
            crandO <- case mcrandO of
                Nothing -> clientRandom ctx
                Just x -> return x
            usingHState ctx $ do
                setClientRandom crandO
                setOuterClientRandom $ Just crandO
            createEncryptedClientHello ctx ch0 echParams crandO
    sendPacket12 ctx $ Handshake [ch]
    mEarlySecInfo <- case rtt0info of
        Nothing -> return Nothing
        Just info -> Just <$> getEarlySecretInfo info
    unless hrr $ contextSync ctx $ SendClientHello mEarlySecInfo
    let sentExtensions = map (\(ExtensionRaw i _) -> i) extensions
    modifyTLS13State ctx $ \st -> st{tls13stSentExtensions = sentExtensions}
  where
    ciphers = supportedCiphers $ ctxSupported ctx
    compressions = supportedCompressions $ ctxSupported ctx
    highestVer = maximum $ supportedVersions $ ctxSupported ctx
    tls13 = highestVer >= TLS13
    ems = supportedExtendedMainSecret $ ctxSupported ctx
    groupToSend = listToMaybe groups

    -- List of extensions to send in ClientHello, ordered such that we never
    -- terminate with a zero-length extension.  Some buggy implementations
    -- are allergic to an extension with empty data at final position.
    --
    -- Without TLS 1.3, the list ends with extension "signature_algorithms"
    -- with length >= 2 bytes.  When TLS 1.3 is enabled, extensions
    -- "psk_key_exchange_modes" (currently always sent) and "pre_shared_key"
    -- (not always present) have length > 0.
    getExtensions =
        sequence
            [ {- 0xfe0d -} echExt
            , {- 0x00 -} sniExt
            , {- 0x0a -} groupExt
            , {- 0x0b -} ecPointExt
            , {- 0x0d -} signatureAlgExt
            , {- 0x10 -} alpnExt
            , {- 0x17 -} emsExt
            , {- 0x1b -} compCertExt
            , {- 0x1c -} recordSizeLimitExt
            , {- 0x23 -} sessionTicketExt
            , {- 0x2a -} earlyDataExt
            , {- 0x2b -} versionExt
            , {- 0x2c -} cookieExt
            , {- 0x2d -} pskExchangeModeExt
            , {- 0x31 -} postHandshakeAuthExt
            , {- 0x33 -} keyShareExt
            , {- 0xff01 -} secureRenegExt
            , {- 0x29 -} preSharedKeyExt -- MUST be last (RFC 8446)
            ]

    --------------------

    sniExt =
        if clientUseServerNameIndication cparams
            then do
                let sni = fst $ clientServerIdentification cparams
                usingState_ ctx $ setClientSNI sni
                return $ Just $ toExtensionRaw $ ServerName [ServerNameHostName sni]
            else return Nothing

    groupExt =
        return $
            Just $
                toExtensionRaw $
                    SupportedGroups (supportedGroups $ ctxSupported ctx)

    ecPointExt =
        return $
            Just $
                toExtensionRaw $
                    EcPointFormatsSupported [EcPointFormat_Uncompressed]

    signatureAlgExt =
        return $
            Just $
                toExtensionRaw $
                    SignatureAlgorithms $
                        supportedHashSignatures $
                            clientSupported cparams

    alpnExt = do
        mprotos <- onSuggestALPN $ clientHooks cparams
        case mprotos of
            Nothing -> return Nothing
            Just protos -> do
                usingState_ ctx $ setClientALPNSuggest protos
                return $ Just $ toExtensionRaw $ ApplicationLayerProtocolNegotiation protos

    emsExt =
        return $
            if ems == NoEMS || all (>= TLS13) (supportedVersions $ ctxSupported ctx)
                then Nothing
                else Just $ toExtensionRaw ExtendedMainSecret

    compCertExt = return $ Just $ toExtensionRaw (CompressCertificate [CCA_Zlib])

    recordSizeLimitExt = case limitRecordSize $ sharedLimit $ ctxShared ctx of
        Nothing -> return Nothing
        Just siz -> return $ Just $ toExtensionRaw $ RecordSizeLimit $ fromIntegral siz

    sessionTicketExt = do
        case clientSessions cparams of
            (sidOrTkt, _) : _
                | isTicket sidOrTkt -> return $ Just $ toExtensionRaw $ SessionTicket sidOrTkt
            _ -> return $ Just $ toExtensionRaw $ SessionTicket ""

    earlyDataExt
        | rtt0 = return $ Just $ toExtensionRaw (EarlyDataIndication Nothing)
        | otherwise = return Nothing

    versionExt
        | isJust mEchParams = do
            let vers = supportedVersions $ ctxSupported ctx
            if TLS13 `elem` vers
                then
                    return $ Just $ toExtensionRaw $ SupportedVersionsClientHello [TLS13]
                else
                    throwCore $ Error_Misc "TLS 1.3 must be specified for Encrypted Client Hello"
        | tls13 = do
            let vers = filter (>= TLS12) $ supportedVersions $ ctxSupported ctx
            return $ Just $ toExtensionRaw $ SupportedVersionsClientHello vers
        | otherwise = return Nothing

    cookieExt = do
        mcookie <- usingState_ ctx getTLS13Cookie
        case mcookie of
            Nothing -> return Nothing
            Just cookie -> return $ Just $ toExtensionRaw cookie

    pskExchangeModeExt
        | tls13 = return $ Just $ toExtensionRaw $ PskKeyExchangeModes [PSK_DHE_KE]
        | otherwise = return Nothing

    postHandshakeAuthExt
        | ctxQUICMode ctx = return Nothing
        | tls13 = return $ Just $ toExtensionRaw PostHandshakeAuth
        | otherwise = return Nothing

    -- FIXME
    keyShareExt
        | tls13 = case groupToSend of
            Nothing -> return Nothing
            Just grp -> do
                (cpri, ent) <- makeClientKeyShare ctx grp
                usingHState ctx $ setGroupPrivate cpri
                return $ Just $ toExtensionRaw $ KeyShareClientHello [ent]
        | otherwise = return Nothing

    secureRenegExt =
        if supportedSecureRenegotiation $ ctxSupported ctx
            then do
                VerifyData cvd <- usingState_ ctx $ getVerifyData ClientRole
                return $ Just $ toExtensionRaw $ SecureRenegotiation cvd ""
            else return Nothing

    echExt = case mEchParams of
        Nothing -> return Nothing
        Just _ -> return $ Just $ toExtensionRaw ECHInner

    preSharedKeyExt =
        case pskInfo of
            Nothing -> return Nothing
            Just (identities, _, choice, obfAge) ->
                let zero = cZero choice
                    pskIdentities = map (\x -> PskIdentity x obfAge) identities
                    -- [zero] is a place holds.
                    -- adjustPreSharedKeyExt will replace them.
                    binders = replicate (length pskIdentities) zero
                    offeredPsks = PreSharedKeyClientHello pskIdentities binders
                 in return $ Just $ toExtensionRaw offeredPsks

    ----------------------------------------

    adjustPreSharedKeyExt exts ch =
        case pskInfo of
            Nothing -> return exts
            Just (identities, sdata, choice, _) -> do
                let psk = sessionSecret sdata
                    earlySecret = initEarlySecret choice (Just psk)
                usingHState ctx $ setTLS13EarlySecret earlySecret
                let ech = encodeHandshake ch
                    h = cHash choice
                    siz = (hashDigestSize h + 1) * length identities + 2
                    binder = makePSKBinder earlySecret h siz ech
                -- PSK is shared by the previous TLS session.
                -- So, PSK is unique for identities.
                let binders = replicate (length identities) binder
                let exts' = init exts ++ [adjust (last exts)]
                    adjust (ExtensionRaw eid withoutBinders) = ExtensionRaw eid withBinders
                      where
                        withBinders = replacePSKBinder withoutBinders binders
                return exts'

    getEarlySecretInfo choice = do
        let usedCipher = cCipher choice
            usedHash = cHash choice
        Just earlySecret <- usingHState ctx getTLS13EarlySecret
        earlyKey <- calculateEarlySecret ctx choice (Right earlySecret)
        let clientEarlySecret = pairClient earlyKey
        unless (ctxQUICMode ctx) $ do
            runPacketFlight ctx $ sendChangeCipherSpec13 ctx
            setTxRecordState ctx usedHash usedCipher clientEarlySecret
            setEstablished ctx EarlyDataSending
        -- We set RTT0Sent even in quicMode
        usingHState ctx $ setTLS13RTT0Status RTT0Sent
        return $ EarlySecretInfo usedCipher clientEarlySecret

----------------------------------------------------------------

type PreSharedKeyInfo =
    ( Maybe ([SessionIDorTicket], SessionData, CipherChoice, Second)
    , Maybe CipherChoice
    , Bool
    )

getPreSharedKeyInfo
    :: ClientParams
    -> Context
    -> IO PreSharedKeyInfo
getPreSharedKeyInfo cparams ctx = do
    pskInfo <- getPskInfo
    let rtt0info = pskInfo >>= get0RTTinfo
        rtt0 = isJust rtt0info
    return (pskInfo, rtt0info, rtt0)
  where
    ciphers = supportedCiphers $ ctxSupported ctx
    highestVer = maximum $ supportedVersions $ ctxSupported ctx
    tls13 = highestVer >= TLS13

    sessions = case clientSessions cparams of
        [] -> Nothing
        (sid, sdata) : xs -> do
            guard tls13
            guard (sessionVersion sdata >= TLS13)
            let cid = sessionCipher sdata
                sids = map fst xs
            sCipher <- findCipher cid ciphers
            Just (sid : sids, sdata, sCipher)

    getPskInfo = case sessions of
        Nothing -> return Nothing
        Just (identity, sdata, sCipher) -> do
            let tinfo = fromJust $ sessionTicketInfo sdata
            age <- getAge tinfo
            return $
                if isAgeValid age tinfo
                    then
                        Just
                            ( identity
                            , sdata
                            , makeCipherChoice TLS13 sCipher
                            , ageToObfuscatedAge age tinfo
                            )
                    else Nothing

    get0RTTinfo (_, sdata, choice, _)
        | clientUseEarlyData cparams && sessionMaxEarlyDataSize sdata > 0 = Just choice
        | otherwise = Nothing

----------------------------------------------------------------

createEncryptedClientHello
    :: Context
    -> Handshake
    -> (KDF_ID, AEAD_ID, ECHConfig)
    -> ClientRandom
    -> IO Handshake
createEncryptedClientHello ctx ch0@(ClientHello ver crI comp chp) echParams@(kdfid, aeadid, conf) crO = E.handle hpkeHandler $ do
    let (chpO, chpI) = dupCompCHP (cnfPublicName conf) chp
        chI = ClientHello ver crI comp chpI
    Just (func, enc, taglen) <- getHPKE ctx echParams
    let bsI = encodeHandshake' chI
    let outer =
            ECHOuter
                { echCipherSuite = (kdfid, aeadid)
                , echConfigId = cnfConfigId conf
                , echEnc = enc
                , echPayload = B.replicate (B.length bsI + taglen) 0
                }
        echOZ = extensionEncode outer
        chpOZ =
            chpO
                { chExtensions =
                    ExtensionRaw EID_EncryptedClientHello echOZ : drop 1 (chExtensions chpO)
                }
        chO = ClientHello ver crO comp chpOZ
        aad = encodeHandshake' chO
    bsO <- func aad bsI
    let outer' =
            ECHOuter
                { echCipherSuite = (kdfid, aeadid)
                , echConfigId = cnfConfigId conf
                , echEnc = enc
                , -- fixme: 16 should be decided from "aeadid"
                  echPayload = bsO
                }
        echO = extensionEncode outer'
    let chpO' =
            chpO
                { chExtensions =
                    ExtensionRaw EID_EncryptedClientHello echO : drop 1 (chExtensions chpO)
                }
    return $ ClientHello ver crO comp chpO'
  where
    hpkeHandler :: HPKEError -> IO Handshake
    hpkeHandler _ = return ch0
createEncryptedClientHello _ _ _ _ = error "createEncryptedClientHello"

dupCompCHP :: HostName -> CHP -> (CHP, CHP) -- Outer, inner
dupCompCHP host CHP{..} =
    ( CHP chSession chCiphers chExtsO
    , CHP (Session Nothing) chCiphers chExtsI
    )
  where
    (chExtsO, chExtsI) = step1 chExtensions
    step1 (echExtI@(ExtensionRaw EID_EncryptedClientHello _) : exts) =
        (echExtO : os, echExtI : is)
      where
        echExtO = ExtensionRaw EID_EncryptedClientHello ""
        (os, is) = step2 exts
    step1 _ = error "step1"
    step2 (sniExtI@(ExtensionRaw EID_ServerName _) : exts) =
        (sniExtO : os, sniExtI : is)
      where
        sniExtO = toExtensionRaw $ ServerName [ServerNameHostName host]
        (os, is) = step3 exts id
    step2 _ = error "step2"
    step3 [] build = ([], [echOuterExt])
      where
        echOuterExt = toExtensionRaw $ EchOuterExtensions $ build []
    step3 [pskExtI@(ExtensionRaw EID_PreSharedKey bs)] build =
        ([pskExtO], [echOuterExt, pskExtI])
      where
        echOuterExt = toExtensionRaw $ EchOuterExtensions $ build []
        pskExtO = ExtensionRaw EID_PreSharedKey $ B.replicate (B.length bs) 120 -- fixme: 120 should be random
    step3 (i@(ExtensionRaw eid _) : is) build = (i : os', is')
      where
        (os', is') = step3 is (build . (eid :))

getHPKE
    :: Context
    -> (KDF_ID, AEAD_ID, ECHConfig)
    -> IO (Maybe (AAD -> PlainText -> IO CipherText, EncodedPublicKey, Int))
getHPKE ctx (kdfid, aeadid, conf) = do
    mfunc <- getTLS13HPKE ctx
    case mfunc of
        Nothing -> do
            encodedConfig <- encodeECHConfig conf
            let info = "tls ech\x00" <> encodedConfig
            (pkSm, ctxS) <- setupBaseS kemid kdfid aeadid Nothing Nothing mpkR info
            let func = seal ctxS
            setTLS13HPKE ctx func 0
            return $ Just (func, pkSm, nT)
        Just (func, _) -> return $ Just (func, EncodedPublicKey "", nT)
  where
    mpkR = cnfEncodedPublicKey conf
    kemid = cnfKemId conf
    nT = nTag aeadid

----------------------------------------------------------------

lookupECHConfigList
    :: [(KEM_ID, KDF_ID, AEAD_ID)]
    -> ECHConfigList
    -> Maybe (KDF_ID, AEAD_ID, ECHConfig)
lookupECHConfigList [] _ = Nothing
lookupECHConfigList ((kemid, kdfid, aeadid) : xs) cnfs =
    case find (\cnf -> cnfKemId cnf == kemid) cnfs of
        Nothing -> lookupECHConfigList xs cnfs
        Just cnf
            | (kdfid, aeadid) `elem` cnfCipherSuite cnf ->
                Just (kdfid, aeadid, cnf)
            | otherwise -> lookupECHConfigList xs cnfs

cnfKemId :: ECHConfig -> KEM_ID
cnfKemId ECHConfig{..} = KEM_ID $ kem_id $ key_config $ contents

cnfCipherSuite :: ECHConfig -> [(KDF_ID, AEAD_ID)]
cnfCipherSuite ECHConfig{..} = map conv $ cipher_suites $ key_config $ contents
  where
    conv HpkeSymmetricCipherSuite{..} = (KDF_ID kdf_id, AEAD_ID aead_id)

cnfEncodedPublicKey :: ECHConfig -> EncodedPublicKey
cnfEncodedPublicKey ECHConfig{..} = EncodedPublicKey pk
  where
    EncodedServerPublicKey pk = public_key $ key_config contents

cnfPublicName :: ECHConfig -> HostName
cnfPublicName ECHConfig{..} = public_name contents

cnfConfigId :: ECHConfig -> ConfigId
cnfConfigId ECHConfig{..} = config_id $ key_config contents
