{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.Client.ClientHello (
    sendClientHello,
    getPreSharedKeyInfo,
) where

import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Client.Common
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Control
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.Random
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
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
    crand <- generateClientHelloParams mparams
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
    -> PreSharedKeyInfo
    -> IO ()
sendClientHello' cparams ctx groups crand (pskInfo, rtt0info, rtt0) = do
    let ver = if tls13 then TLS12 else highestVer
    clientSession <- tls13stSession <$> getTLS13State ctx
    hrr <- usingState_ ctx getTLS13HRR
    unless hrr $ startHandshake ctx ver crand
    usingState_ ctx $ setVersionIfUnset highestVer
    let cipherIds = map cipherID ciphers
        compIds = map compressionID compressions
        mkClientHello exts = ClientHello ver crand compIds $ CH clientSession cipherIds exts
    extensions0 <- catMaybes <$> getExtensions
    let extensions1 = sharedHelloExtensions (clientShared cparams) ++ extensions0
    extensions <- adjustExtentions extensions1 $ mkClientHello extensions1
    sendPacket12 ctx $ Handshake [mkClientHello extensions]
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
            [ sniExtension
            , secureReneg
            , alpnExtension
            , emsExtension
            , groupExtension
            , ecPointExtension
            , sessionTicketExtension
            , signatureAlgExtension
            , -- , heartbeatExtension
              versionExtension
            , earlyDataExtension
            , keyshareExtension
            , cookieExtension
            , postHandshakeAuthExtension
            , pskExchangeModeExtension
            , preSharedKeyExtension -- MUST be last (RFC 8446)
            ]

    secureReneg =
        if supportedSecureRenegotiation $ ctxSupported ctx
            then do
                VerifyData cvd <- usingState_ ctx $ getVerifyData ClientRole
                return $ Just $ toExtensionRaw $ SecureRenegotiation cvd ""
            else return Nothing
    alpnExtension = do
        mprotos <- onSuggestALPN $ clientHooks cparams
        case mprotos of
            Nothing -> return Nothing
            Just protos -> do
                usingState_ ctx $ setClientALPNSuggest protos
                return $ Just $ toExtensionRaw $ ApplicationLayerProtocolNegotiation protos
    emsExtension =
        return $
            if ems == NoEMS || all (>= TLS13) (supportedVersions $ ctxSupported ctx)
                then Nothing
                else Just $ toExtensionRaw ExtendedMainSecret
    sniExtension =
        if clientUseServerNameIndication cparams
            then do
                let sni = fst $ clientServerIdentification cparams
                usingState_ ctx $ setClientSNI sni
                return $ Just $ toExtensionRaw $ ServerName [ServerNameHostName sni]
            else return Nothing

    groupExtension =
        return $
            Just $
                toExtensionRaw $
                    SupportedGroups (supportedGroups $ ctxSupported ctx)
    ecPointExtension =
        return $
            Just $
                toExtensionRaw $
                    EcPointFormatsSupported [EcPointFormat_Uncompressed]
    -- [EcPointFormat_Uncompressed,EcPointFormat_AnsiX962_compressed_prime,EcPointFormat_AnsiX962_compressed_char2]
    -- heartbeatExtension = return $ Just $ toExtensionRaw $ HeartBeat $ HeartBeat_PeerAllowedToSend

    sessionTicketExtension = do
        case clientSessions cparams of
            (sidOrTkt, _) : _
                | isTicket sidOrTkt -> return $ Just $ toExtensionRaw $ SessionTicket sidOrTkt
            _ -> return $ Just $ toExtensionRaw $ SessionTicket ""

    signatureAlgExtension =
        return $
            Just $
                toExtensionRaw $
                    SignatureAlgorithms $
                        supportedHashSignatures $
                            clientSupported cparams

    versionExtension
        | tls13 = do
            let vers = filter (>= TLS12) $ supportedVersions $ ctxSupported ctx
            return $ Just $ toExtensionRaw $ SupportedVersionsClientHello vers
        | otherwise = return Nothing

    -- FIXME
    keyshareExtension
        | tls13 = case groupToSend of
            Nothing -> return Nothing
            Just grp -> do
                (cpri, ent) <- makeClientKeyShare ctx grp
                usingHState ctx $ setGroupPrivate cpri
                return $ Just $ toExtensionRaw $ KeyShareClientHello [ent]
        | otherwise = return Nothing

    preSharedKeyExtension =
        case pskInfo of
            Nothing -> return Nothing
            Just (identities, _, choice, obfAge) ->
                let zero = cZero choice
                    pskIdentities = map (\x -> PskIdentity x obfAge) identities
                    -- [zero] is a place holds.
                    -- adjustExtentions will replace them.
                    binders = replicate (length pskIdentities) zero
                    offeredPsks = PreSharedKeyClientHello pskIdentities binders
                 in return $ Just $ toExtensionRaw offeredPsks

    pskExchangeModeExtension
        | tls13 = return $ Just $ toExtensionRaw $ PskKeyExchangeModes [PSK_DHE_KE]
        | otherwise = return Nothing

    earlyDataExtension
        | rtt0 = return $ Just $ toExtensionRaw (EarlyDataIndication Nothing)
        | otherwise = return Nothing

    cookieExtension = do
        mcookie <- usingState_ ctx getTLS13Cookie
        case mcookie of
            Nothing -> return Nothing
            Just cookie -> return $ Just $ toExtensionRaw cookie

    postHandshakeAuthExtension
        | ctxQUICMode ctx = return Nothing
        | tls13 = return $ Just $ toExtensionRaw PostHandshakeAuth
        | otherwise = return Nothing

    adjustExtentions exts ch =
        case pskInfo of
            Nothing -> return exts
            Just (identities, sdata, choice, _) -> do
                let psk = sessionSecret sdata
                    earlySecret = initEarlySecret choice (Just psk)
                usingHState ctx $ setTLS13EarlySecret earlySecret
                let ech = encodeHandshake ch
                    h = cHash choice
                    siz = (hashDigestSize h + 1) * length identities + 2
                binder <- makePSKBinder ctx earlySecret h siz (Just ech)
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
        -- Client hello is stored in hstHandshakeDigest
        -- But HandshakeDigestContext is not created yet.
        earlyKey <- calculateEarlySecret ctx choice (Right earlySecret) False
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
            sCipher <- find (\c -> cipherID c == cid) ciphers
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
