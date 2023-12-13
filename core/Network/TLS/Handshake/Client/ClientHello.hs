{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.Client.ClientHello (
    sendClientHello,
) where

import qualified Data.ByteString as B
import Data.Maybe (fromJust)

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
import Network.TLS.Struct13
import Network.TLS.Types
import Network.TLS.Util (mapChunks_)

----------------------------------------------------------------

sendClientHello
    :: ClientParams
    -> Context
    -> [Group]
    -> Maybe (ClientRandom, Session, c)
    -> IO (ClientRandom, Session, Bool, [ExtensionID])
sendClientHello cparams ctx groups mparams = do
    (crand, clientSession) <- generateClientHelloParams mparams
    (rtt0, sentExtensions) <-
        sendClientHello' cparams ctx groups clientSession crand
    return (crand, clientSession, rtt0, sentExtensions)
  where
    highestVer = maximum $ supportedVersions $ ctxSupported ctx
    tls13 = highestVer >= TLS13
    ems = supportedExtendedMasterSec $ ctxSupported ctx

    -- Client random and session in the second client hello for
    -- retry must be the same as the first one.
    generateClientHelloParams (Just (crand, clientSession, _)) =
        return (crand, clientSession)
    generateClientHelloParams Nothing = do
        crand <- clientRandom ctx
        let paramSession = case clientWantSessionResume cparams of
                Nothing -> Session Nothing
                Just (sidOrTkt, sdata)
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
                return (crand, randomSession)
            else return (crand, paramSession)

----------------------------------------------------------------

sendClientHello'
    :: ClientParams
    -> Context
    -> [Group]
    -> Session
    -> ClientRandom
    -> IO (Bool, [ExtensionID])
sendClientHello' cparams ctx groups clientSession crand = do
    let ver = if tls13 then TLS12 else highestVer
    hrr <- usingState_ ctx getTLS13HRR
    unless hrr $ startHandshake ctx ver crand
    usingState_ ctx $ setVersionIfUnset highestVer
    let cipherIds = map cipherID ciphers
        compIds = map compressionID compressions
        mkClientHello exts = ClientHello ver crand compIds $ CH clientSession cipherIds exts
    pskInfo <- getPskInfo
    let rtt0info = pskInfo >>= get0RTTinfo
        rtt0 = isJust rtt0info
    extensions0 <- catMaybes <$> getExtensions pskInfo rtt0
    let extensions1 = sharedHelloExtensions (clientShared cparams) ++ extensions0
    extensions <- adjustExtentions pskInfo extensions1 $ mkClientHello extensions1
    sendPacket ctx $ Handshake [mkClientHello extensions]
    mEarlySecInfo <- case rtt0info of
        Nothing -> return Nothing
        Just info -> Just <$> send0RTT info
    unless hrr $ contextSync ctx $ SendClientHello mEarlySecInfo
    return (rtt0, map (\(ExtensionRaw i _) -> i) extensions)
  where
    ciphers = supportedCiphers $ ctxSupported ctx
    compressions = supportedCompressions $ ctxSupported ctx
    highestVer = maximum $ supportedVersions $ ctxSupported ctx
    tls13 = highestVer >= TLS13
    ems = supportedExtendedMasterSec $ ctxSupported ctx
    groupToSend = listToMaybe groups

    -- List of extensions to send in ClientHello, ordered such that we never
    -- terminate with a zero-length extension.  Some buggy implementations
    -- are allergic to an extension with empty data at final position.
    --
    -- Without TLS 1.3, the list ends with extension "signature_algorithms"
    -- with length >= 2 bytes.  When TLS 1.3 is enabled, extensions
    -- "psk_key_exchange_modes" (currently always sent) and "pre_shared_key"
    -- (not always present) have length > 0.
    getExtensions pskInfo rtt0 =
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
            , earlyDataExtension rtt0
            , keyshareExtension
            , cookieExtension
            , postHandshakeAuthExtension
            , pskExchangeModeExtension
            , preSharedKeyExtension pskInfo -- MUST be last (RFC 8446)
            ]

    toExtensionRaw :: Extension e => e -> ExtensionRaw
    toExtensionRaw ext = ExtensionRaw (extensionID ext) (extensionEncode ext)

    secureReneg =
        if supportedSecureRenegotiation $ ctxSupported ctx
            then
                usingState_ ctx (getVerifiedData ClientRole) >>= \vd -> return $ Just $ toExtensionRaw $ SecureRenegotiation vd Nothing
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
                else Just $ toExtensionRaw ExtendedMasterSecret
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
        case clientWantSessionResume cparams of
          Nothing -> return $ Just $ toExtensionRaw $ SessionTicket ""
          Just (sidOrTkt, sdata)
            | sessionVersion sdata >= TLS13 -> return Nothing
            | isTicket sidOrTkt -> return $ Just $ toExtensionRaw $ SessionTicket sidOrTkt
            | otherwise -> return Nothing

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

    sessionAndCipherToResume13 = do
        guard tls13
        (sid, sdata) <- clientWantSessionResume cparams
        guard (sessionVersion sdata >= TLS13)
        sCipher <- find (\c -> cipherID c == sessionCipher sdata) ciphers
        return (sid, sdata, sCipher)

    getPskInfo =
        case sessionAndCipherToResume13 of
            Nothing -> return Nothing
            Just (identity, sdata, sCipher) -> do
                let tinfo = fromJust $ sessionTicketInfo sdata
                age <- getAge tinfo
                return $
                    if isAgeValid age tinfo
                        then Just (identity, sdata, makeCipherChoice TLS13 sCipher, ageToObfuscatedAge age tinfo)
                        else Nothing

    preSharedKeyExtension pskInfo =
        case pskInfo of
            Nothing -> return Nothing
            Just (identity, _, choice, obfAge) ->
                let zero = cZero choice
                    pskIdentity = PskIdentity identity obfAge
                    offeredPsks = PreSharedKeyClientHello [pskIdentity] [zero]
                 in return $ Just $ toExtensionRaw offeredPsks

    pskExchangeModeExtension
        | tls13 = return $ Just $ toExtensionRaw $ PskKeyExchangeModes [PSK_DHE_KE]
        | otherwise = return Nothing

    earlyDataExtension rtt0
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

    send0RTT (choice, earlyData) = do
        let usedCipher = cCipher choice
            usedHash = cHash choice
        Just earlySecret <- usingHState ctx getTLS13EarlySecret
        -- Client hello is stored in hstHandshakeDigest
        -- But HandshakeDigestContext is not created yet.
        earlyKey <- calculateEarlySecret ctx choice (Right earlySecret) False
        let clientEarlySecret = pairClient earlyKey
        unless (ctxQUICMode ctx) $ do
            runPacketFlight ctx $ sendChangeCipherSpec13 ctx
            setTxState ctx usedHash usedCipher clientEarlySecret
            let len = ctxFragmentSize ctx
            mapChunks_ len (sendPacket13 ctx . AppData13) earlyData
        -- We set RTT0Sent even in quicMode
        usingHState ctx $ setTLS13RTT0Status RTT0Sent
        return $ EarlySecretInfo usedCipher clientEarlySecret
