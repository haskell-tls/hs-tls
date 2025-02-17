{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.TLS.Handshake.Server.ClientHello (
    processClientHello,
) where

import Crypto.HPKE
import qualified Data.ByteString as BS
import Network.TLS.ECH.Config

import Network.TLS.Compression
import Network.TLS.Context.Internal
import Network.TLS.Extension
import Network.TLS.Handshake.Process
import Network.TLS.Imports
import Network.TLS.Measurement
import Network.TLS.Packet
import Network.TLS.Parameters
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Types

processClientHello
    :: ServerParams -> Context -> Handshake -> IO (Version, CH, Bool)
processClientHello sparams ctx clientHello@(ClientHello legacyVersion cran compressions ch@CH{..}) = do
    established <- ctxEstablished ctx
    -- renego is not allowed in TLS 1.3
    when (established /= NotEstablished) $ do
        ver <- usingState_ ctx (getVersionWithDefault TLS12)
        when (ver == TLS13) $
            throwCore $
                Error_Protocol "renegotiation is not allowed in TLS 1.3" UnexpectedMessage
    -- rejecting client initiated renegotiation to prevent DOS.
    eof <- ctxEOF ctx
    let renegotiation = established == Established && not eof
    when
        (renegotiation && not (supportedClientInitiatedRenegotiation $ ctxSupported ctx))
        $ throwCore
        $ Error_Protocol_Warning "renegotiation is not allowed" NoRenegotiation
    -- check if policy allow this new handshake to happens
    handshakeAuthorized <- withMeasure ctx (onNewHandshake $ serverHooks sparams)
    unless
        handshakeAuthorized
        (throwCore $ Error_HandshakePolicy "server: handshake denied")
    updateMeasure ctx incrementNbHandshakes

    when (legacyVersion /= TLS12) $
        throwCore $
            Error_Protocol (show legacyVersion ++ " is not supported") ProtocolVersion

    -- Fallback SCSV: RFC7507
    -- TLS_FALLBACK_SCSV: {0x56, 0x00}
    when
        ( supportedFallbackScsv (ctxSupported ctx)
            && (CipherId 0x5600 `elem` chCiphers)
            && legacyVersion < TLS12
        )
        $ throwCore
        $ Error_Protocol "fallback is not allowed" InappropriateFallback

    -- choosing TLS version
    let extract (SupportedVersionsClientHello vers) = vers -- fixme: vers == []
        extract _ = []
        clientVersions = lookupAndDecode EID_SupportedVersions MsgTClientHello chExtensions [] extract
        clientVersion = min TLS12 legacyVersion
        serverVersions
            | renegotiation = filter (< TLS13) (supportedVersions $ ctxSupported ctx)
            | otherwise = supportedVersions $ ctxSupported ctx
        mVersion = debugVersionForced $ serverDebug sparams
    chosenVersion <- case mVersion of
        Just cver -> return cver
        Nothing ->
            if (TLS13 `elem` serverVersions) && clientVersions /= []
                then case findHighestVersionFrom13 clientVersions serverVersions of
                    Nothing ->
                        throwCore $
                            Error_Protocol
                                ("client versions " ++ show clientVersions ++ " is not supported")
                                ProtocolVersion
                    Just v -> return v
                else case findHighestVersionFrom clientVersion serverVersions of
                    Nothing ->
                        throwCore $
                            Error_Protocol
                                ("client version " ++ show clientVersion ++ " is not supported")
                                ProtocolVersion
                    Just v -> return v

    -- Checking compression
    let nullComp = compressionID nullCompression
    case chosenVersion of
        TLS13 ->
            when (compressions /= [nullComp]) $
                throwCore $
                    Error_Protocol "compression is not allowed in TLS 1.3" IllegalParameter
        _ -> case find (== nullComp) compressions of
            Nothing ->
                throwCore $
                    Error_Protocol
                        "compressions must include nullCompression in TLS 1.2"
                        IllegalParameter
            _ -> return ()

    -- Processing encrypted client hello
    mClientHello' <-
        if chosenVersion == TLS13
            then do
                lookupAndDecodeAndDo
                    EID_EncryptedClientHello
                    MsgTClientHello
                    chExtensions
                    (return Nothing)
                    (decryptECH sparams clientHello)
            else return Nothing
    case mClientHello' of
        Just clientHello'@(ClientHello _ cran' _ ch') -> do
            hrr <- usingState_ ctx getTLS13HRR
            unless hrr $ startHandshake ctx legacyVersion cran'
            let serverName = getServerName ch'
            maybe (return ()) (usingState_ ctx . setClientSNI) serverName
            processHandshake12 ctx clientHello'
            return (chosenVersion, ch', True)
        _ -> do
            hrr <- usingState_ ctx getTLS13HRR
            unless hrr $ startHandshake ctx legacyVersion cran
            let serverName = getServerName ch
            maybe (return ()) (usingState_ ctx . setClientSNI) serverName
            processHandshake12 ctx clientHello
            return (chosenVersion, ch, False)
processClientHello _ _ _ =
    throwCore $
        Error_Protocol
            "unexpected handshake message received in handshakeServerWith"
            HandshakeFailure

-- SNI (Server Name Indication)
getServerName :: CH -> Maybe HostName
getServerName CH{..} =
    lookupAndDecode
        EID_ServerName
        MsgTClientHello
        chExtensions
        Nothing
        extractServerName
  where
    extractServerName (ServerName ns) = listToMaybe (mapMaybe toHostName ns)
    toHostName (ServerNameHostName hostName) = Just hostName
    toHostName (ServerNameOther _) = Nothing

findHighestVersionFrom :: Version -> [Version] -> Maybe Version
findHighestVersionFrom clientVersion allowedVersions =
    case filter (clientVersion >=) $ sortOn Down allowedVersions of
        [] -> Nothing
        v : _ -> Just v

findHighestVersionFrom13 :: [Version] -> [Version] -> Maybe Version
findHighestVersionFrom13 clientVersions serverVersions = case svs `intersect` cvs of
    [] -> Nothing
    v : _ -> Just v
  where
    svs = sortOn Down serverVersions
    cvs = sortOn Down $ filter (>= TLS12) clientVersions

decryptECH
    :: ServerParams -> Handshake -> ECHClientHello -> IO (Maybe Handshake)
decryptECH _ _ ECHInner = return Nothing
decryptECH ServerParams{..} clientHello@(ClientHello _ _ _ outerCH) ECHOuter{..} = case (mconfig, mskR) of
    (Just config, Just skR') -> do
        let kemid = KEM_ID $ kem_id $ key_config $ contents config
            skR = EncodedSecretKey skR'
        encodedConfig <- encodeECHConfig config
        let info = "tls ech\x00" <> encodedConfig
        ctxR <- setupBaseR kemid kdfid aeadid skR Nothing echEnc info
        let nenc = nEnc kemid
        let aad = encodeHandshake' $ fill0ClientHello nenc clientHello
        plaintext <- open ctxR aad echPayload
        case decodeClientHello' plaintext of
            Right (ClientHello v r c innerCH) -> do
                case expandClientHello innerCH outerCH of
                    Nothing -> return Nothing
                    Just innerCH' -> return $ Just $ ClientHello v r c innerCH'
            _ -> return Nothing
    _ -> return Nothing
  where
    eqCfgId cnf = config_id (key_config (contents cnf)) == echConfigId
    mconfig = find eqCfgId $ sharedECHConfig serverShared
    mskR = lookup echConfigId serverECHKey
    (kdfid, aeadid) = echCipherSuite
decryptECH _ _ _ = return Nothing

fill0ClientHello :: Int -> Handshake -> Handshake
fill0ClientHello nenc (ClientHello ver rnd cs ch) =
    ClientHello ver rnd cs $ ch{chExtensions = fill0Exts nenc (chExtensions ch)}
fill0ClientHello _ _ = error "fill0ClientHello"

fill0Exts :: Int -> [ExtensionRaw] -> [ExtensionRaw]
fill0Exts nenc xs0 = loop xs0
  where
    loop [] = []
    loop (ExtensionRaw EID_EncryptedClientHello bs : xs) = x' : loop xs
      where
        (prefix, payload) = BS.splitAt (10 + nenc) bs
        bs' = prefix <> BS.replicate (BS.length payload) 0
        x' = ExtensionRaw EID_EncryptedClientHello bs'
    loop (x : xs) = x : loop xs

expandClientHello :: CH -> CH -> Maybe CH
expandClientHello inner outer =
    case expand (chExtensions inner) (chExtensions outer) of
        Nothing -> Nothing
        Just exts ->
            Just $
                inner
                    { chSession = chSession outer
                    , chExtensions = exts
                    }
  where
    expand :: [ExtensionRaw] -> [ExtensionRaw] -> Maybe [ExtensionRaw]
    expand [] _ = Just []
    expand iis [] = chk iis
    expand (i : is) oos = do
        (rs, oos') <- case i of
            ExtensionRaw EID_EchOuterExtensions bs ->
                case extensionDecode MsgTClientHello bs of
                    Nothing -> Nothing
                    Just (EchOuterExtensions eids) -> expd eids oos
            _ -> Just ([i], oos)
        (rs ++) <$> expand is oos'
    expd
        :: [ExtensionID] -> [ExtensionRaw] -> Maybe ([ExtensionRaw], [ExtensionRaw])
    expd [] oos = Just ([], oos)
    expd _ [] = Nothing
    expd (i : is) oos = case fnd i oos of
        Nothing -> Nothing
        Just (ext, oos') -> do
            (exts, oos'') <- expd is oos'
            Just (ext : exts, oos'')
    fnd :: ExtensionID -> [ExtensionRaw] -> Maybe (ExtensionRaw, [ExtensionRaw])
    fnd _ [] = Nothing
    fnd EID_EncryptedClientHello _ = Nothing
    fnd i (o@(ExtensionRaw eid _) : os)
        | i == eid = Just (o, os)
        | otherwise = fnd i os
    chk :: [ExtensionRaw] -> Maybe [ExtensionRaw]
    chk [] = Just []
    chk (ExtensionRaw EID_EchOuterExtensions _ : _) = Nothing
    chk (i : is) = (i :) <$> chk is
