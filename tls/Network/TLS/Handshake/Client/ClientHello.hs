{-# LANGUAGE CPP #-}
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
import System.Random

#if !MIN_VERSION_random(1,3,0)
import Data.ByteString.Internal (unsafeCreate)
import Foreign.Ptr
import Foreign.Storable
#endif

import Network.TLS.Cipher
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
    sendClientHello' cparams ctx groups crand pskinfo
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
    -> IO ()
sendClientHello' cparams ctx groups crand (pskInfo, rtt0info, rtt0) = do
    let ver = if tls13 then TLS12 else highestVer
    clientSession <- tls13stSession <$> getTLS13State ctx
    hrr <- usingState_ ctx getTLS13HRR
    unless hrr $ startHandshake ctx ver crand
    usingState_ ctx $ setVersionIfUnset highestVer
    let cipherIds = map (CipherId . cipherID) ciphers
        mkClientHello exts =
            CH
                { chVersion = ver
                , chRandom = crand
                , chSession = clientSession
                , chCiphers = cipherIds
                , chComps = [0]
                , chExtensions = exts
                }
    setMyRecordLimit ctx $ limitRecordSize $ sharedLimit $ ctxShared ctx
    extensions0 <- catMaybes <$> getExtensions
    let extensions1 = sharedHelloExtensions (clientShared cparams) ++ extensions0
    extensions <- adjustPreSharedKeyExt extensions1 $ mkClientHello extensions1
    let ch0 = mkClientHello extensions
    updateTranscriptHashI ctx "ClientHelloI" $ encodeHandshake $ ClientHello ch0
    let nhpks = supportedHPKE $ clientSupported cparams
        echcnfs = sharedECHConfigList $ clientShared cparams
        mEchParams = lookupECHConfigList nhpks echcnfs
    ch <-
        if clientUseECH cparams
            then case mEchParams of
                Nothing -> do
                    if hrr
                        then do
                            (chI, _) <- fromJust <$> usingHState ctx getClientHello
                            let ch0' = ch0{chExtensions = take 1 (chExtensions chI) ++ drop 1 (chExtensions ch0)}
                            -- [] will be overridden via
                            -- encodeUpdateTranscriptHash12
                            usingHState ctx $ setClientHello ch0' []
                            return ch0'
                        else do
                            gEchExt <- greasingEchExt
                            let ch0' = ch0{chExtensions = gEchExt : drop 1 (chExtensions ch0)}
                            -- [] will be overridden via
                            -- encodeUpdateTranscriptHash12
                            usingHState ctx $ setClientHello ch0' []
                            return ch0'
                Just echParams -> do
                    let encoded = encodeHandshake $ ClientHello ch0
                    usingHState ctx $ setClientHello ch0 [encoded]
                    mcrandO <- usingHState ctx getOuterClientRandom
                    crandO <- case mcrandO of
                        Nothing -> clientRandom ctx
                        Just x -> return x
                    usingHState ctx $ do
                        setClientRandom crandO
                        setOuterClientRandom $ Just crandO
                    mpskExt <- randomPreSharedKeyExt
                    createEncryptedClientHello ctx ch0 echParams crandO mpskExt
            else do
                -- [] will be overridden via
                -- encodeUpdateTranscriptHash12
                usingHState ctx $ setClientHello ch0 []
                return ch0
    sendPacket12 ctx $ Handshake [ClientHello ch] []
    mEarlySecInfo <- case rtt0info of
        Nothing -> return Nothing
        Just info -> Just <$> getEarlySecretInfo info
    unless hrr $ contextSync ctx $ SendClientHello mEarlySecInfo
    let sentExtensions = map (\(ExtensionRaw i _) -> i) extensions
    modifyTLS13State ctx $ \st -> st{tls13stSentExtensions = sentExtensions}
  where
    ciphers = supportedCiphers $ ctxSupported ctx
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
            , --          , {- 0x1b -} compCertExt
              {- 0x1c -} recordSizeLimitExt
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

    --    compCertExt = return $ Just $ toExtensionRaw (CompressCertificate [CCA_Zlib])

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
        | clientUseECH cparams = do
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

    -- ECHClientHelloInner should be replaced if ECHConfigList is not available.
    echExt
        | clientUseECH cparams = return $ Just $ toExtensionRaw ECHClientHelloInner
        | otherwise = return Nothing

    preSharedKeyExt =
        case pskInfo of
            Nothing -> return Nothing
            Just (identities, _, choice, obfAge) -> do
                let zero = cZero choice
                    pskIdentities = map (\x -> PskIdentity x obfAge) identities
                    -- [zero] is a place holds.
                    -- adjustPreSharedKeyExt will replace them.
                    binders = replicate (length pskIdentities) zero
                    offeredPsks = PreSharedKeyClientHello pskIdentities binders
                return $ Just $ toExtensionRaw offeredPsks

    randomPreSharedKeyExt :: IO (Maybe ExtensionRaw)
    randomPreSharedKeyExt =
        case pskInfo of
            Nothing -> return Nothing
            Just (identities, _, choice, _) -> do
                let zero = cZero choice
                zeroR <- getStdRandom $ uniformByteString $ B.length zero
                obfAgeR <- getStdRandom genWord32
                let genPskId x = do
                        xR <- getStdRandom $ uniformByteString $ B.length x
                        return $ PskIdentity xR obfAgeR
                pskIdentitiesR <- mapM genPskId identities
                let bindersR = replicate (length pskIdentitiesR) zeroR
                    offeredPsksR = PreSharedKeyClientHello pskIdentitiesR bindersR
                return $ Just $ toExtensionRaw offeredPsksR

    ----------------------------------------

    adjustPreSharedKeyExt exts ch =
        case pskInfo of
            Nothing -> return exts
            Just (identities, sdata, choice, _) -> do
                let psk = sessionSecret sdata
                    earlySecret = initEarlySecret choice (Just psk)
                usingHState ctx $ setTLS13EarlySecret earlySecret
                let ech = encodeHandshake $ ClientHello ch
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
    -> ClientHello
    -> (KDF_ID, AEAD_ID, ECHConfig)
    -> ClientRandom
    -> Maybe ExtensionRaw
    -> IO ClientHello
createEncryptedClientHello ctx ch0@CH{..} echParams@(kdfid, aeadid, conf) crO mpskExt = E.handle hpkeHandler $ do
    let (chExtsO, chExtsI) = dupCompExts (cnfPublicName conf) mpskExt chExtensions
        chI =
            ch0
                { chSession = Session Nothing
                , chExtensions = chExtsI
                }
    Just (func, enc, taglen) <- getHPKE ctx echParams
    let bsI = encodeHandshake' $ ClientHello chI
        padLen = 32 - (B.length bsI .&. 31)
        bsI' = bsI <> B.replicate padLen 0
    let outerZ =
            ECHClientHelloOuter
                { echCipherSuite = (kdfid, aeadid)
                , echConfigId = cnfConfigId conf
                , echEnc = enc
                , echPayload = B.replicate (B.length bsI' + taglen) 0
                }
        echOZ = extensionEncode outerZ
        chExtsOTail = drop 1 chExtsO
        chOZ =
            ch0
                { chRandom = crO
                , chExtensions =
                    ExtensionRaw EID_EncryptedClientHello echOZ : chExtsOTail
                }
        aad = encodeHandshake' $ ClientHello chOZ
    bsO <- func aad bsI'
    let outer =
            ECHClientHelloOuter
                { echCipherSuite = (kdfid, aeadid)
                , echConfigId = cnfConfigId conf
                , echEnc = enc
                , echPayload = bsO
                }
        echO = extensionEncode outer
        chO =
            chOZ
                { chExtensions =
                    ExtensionRaw EID_EncryptedClientHello echO : chExtsOTail
                }
    return chO
  where
    hpkeHandler :: HPKEError -> IO ClientHello
    hpkeHandler _ = return ch0

dupCompExts
    :: HostName
    -> Maybe ExtensionRaw
    -> [ExtensionRaw]
    -> ([ExtensionRaw], [ExtensionRaw]) -- Outer, inner
dupCompExts host mpskExt chExts = step1 chExts
  where
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
    step3 [pskExtI@(ExtensionRaw EID_PreSharedKey _)] build =
        ([pskExtO], [echOuterExt, pskExtI])
      where
        echOuterExt = toExtensionRaw $ EchOuterExtensions $ build []
        pskExtO = fromJust mpskExt
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
            let encodedConfig = encodeECHConfig conf
                info = "tls ech\x00" <> encodedConfig
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
cnfKemId ECHConfig{..} = KEM_ID $ kem_id $ key_config contents

cnfCipherSuite :: ECHConfig -> [(KDF_ID, AEAD_ID)]
cnfCipherSuite ECHConfig{..} = map conv $ cipher_suites $ key_config contents
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

----------------------------------------------------------------

-- Pretending X25519 is used because it is the de-facto and
-- its public key is easily created.
greasingEchExt :: IO ExtensionRaw
greasingEchExt = do
    cid <- getStdRandom genWord8
    enc <- getStdRandom $ uniformByteString 32
    n <- getStdRandom $ randomR (4, 6)
    payload <- getStdRandom $ uniformByteString (n * 32 + 16)
    let outer =
            ECHClientHelloOuter
                { echCipherSuite = (HKDF_SHA256, AES_128_GCM)
                , echConfigId = cid
                , echEnc = EncodedPublicKey enc
                , echPayload = payload
                }
    return $ toExtensionRaw outer

#if !MIN_VERSION_random(1,3,0)
uniformByteString :: RandomGen g => Int -> g -> (ByteString, g)
uniformByteString l g0 = (bs, g2)
  where
    (g1, g2) = split g0
    bs = unsafeCreate l $ go 0 g1
    go n g ptr
        | n == l = return ()
        | otherwise = do
            let (w, g') = genWord8 g
            poke ptr w
            go (n + 1) g' (plusPtr ptr 1)
#endif
