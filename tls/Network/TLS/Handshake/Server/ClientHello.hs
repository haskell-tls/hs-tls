{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module Network.TLS.Handshake.Server.ClientHello (
    processClientHello,
) where

import qualified Control.Exception as E
import Crypto.HPKE
import qualified Data.ByteString as BS

import Network.TLS.ECH.Config

import Network.TLS.Compression
import Network.TLS.Context.Internal
import Network.TLS.Extension
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.State
import Network.TLS.Imports
import Network.TLS.Measurement
import Network.TLS.Packet
import Network.TLS.Parameters
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Types

processClientHello
    :: ServerParams
    -> Context
    -> ClientHello
    -> IO
        ( Version
        , ClientHello
        , Maybe ClientRandom -- Just for ECH to keep the outer one for key log
        )
processClientHello sparams ctx ch@CH{..} = do
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

    when (chVersion /= TLS12) $
        throwCore $
            Error_Protocol (show chVersion ++ " is not supported") ProtocolVersion

    -- Fallback SCSV: RFC7507
    -- TLS_FALLBACK_SCSV: {0x56, 0x00}
    when
        ( supportedFallbackScsv (ctxSupported ctx)
            && (CipherId 0x5600 `elem` chCiphers)
            && chVersion < TLS12
        )
        $ throwCore
        $ Error_Protocol "fallback is not allowed" InappropriateFallback

    -- choosing TLS version
    let extract (SupportedVersionsClientHello vers) = vers -- fixme: vers == []
        extract _ = []
        clientVersions =
            lookupAndDecode EID_SupportedVersions MsgTClientHello chExtensions [] extract
        clientVersion = min TLS12 chVersion
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
            when (chComps /= [nullComp]) $
                throwCore $
                    Error_Protocol "compression is not allowed in TLS 1.3" IllegalParameter
        _ -> case find (== nullComp) chComps of
            Nothing ->
                throwCore $
                    Error_Protocol
                        "compressions must include nullCompression in TLS 1.2"
                        IllegalParameter
            _ -> return ()

    -- Processing encrypted client hello
    (mClientHello', receivedECH) <-
        if chosenVersion == TLS13 && not (null (serverECHKey sparams))
            then do
                lookupAndDecodeAndDo
                    EID_EncryptedClientHello
                    MsgTClientHello
                    chExtensions
                    (return (Nothing, False))
                    (\bs -> (,True) <$> decryptECH sparams ctx ch bs)
            else return (Nothing, False)
    case mClientHello' of
        Just chI -> do
            setupI ctx chI
            return (chosenVersion, chI, Just chRandom)
        _ -> do
            setupO ctx ch
            when (chosenVersion == TLS13) $ do
                let hasECHConf = not (null (sharedECHConfigList (serverShared sparams)))
                when (hasECHConf && not receivedECH) $
                    usingHState ctx $
                        setECHEE True
                when receivedECH $
                    usingHState ctx $
                        setECHEE True
            return (chosenVersion, ch, Nothing)

setupI :: Context -> ClientHello -> IO ()
setupI ctx chI@CH{..} = do
    hrr <- usingState_ ctx getTLS13HRR
    unless hrr $ startHandshake ctx TLS13 chRandom
    usingHState ctx $ setClientHello chI
    let serverName = getServerName chExtensions
    maybe (return ()) (usingState_ ctx . setClientSNI) serverName

setupO :: Context -> ClientHello -> IO ()
setupO ctx ch@CH{..} = do
    hrr <- usingState_ ctx getTLS13HRR
    unless hrr $ startHandshake ctx chVersion chRandom
    usingHState ctx $ setClientHello ch
    let serverName = getServerName chExtensions
    maybe (return ()) (usingState_ ctx . setClientSNI) serverName

-- SNI (Server Name Indication)
getServerName :: [ExtensionRaw] -> Maybe HostName
getServerName chExts =
    lookupAndDecode
        EID_ServerName
        MsgTClientHello
        chExts
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
    :: ServerParams
    -> Context
    -> ClientHello
    -> EncryptedClientHello
    -> IO (Maybe ClientHello)
decryptECH _ _ _ ECHClientHelloInner = return Nothing
decryptECH sparams ctx chO ech@ECHClientHelloOuter{..} = E.handle hpkeHandler $ do
    mfunc <- getHPKE sparams ctx ech
    case mfunc of
        Nothing -> return Nothing
        Just (func, nenc) -> do
            hrr <- usingState_ ctx getTLS13HRR
            let nenc' = if hrr then 0 else nenc
            let aad = encodeHandshake' $ ClientHello $ fill0ClientHello nenc' chO
            plaintext <- func aad echPayload
            case decodeClientHello' plaintext of
                Right (ClientHello chI) -> do
                    case expandClientHello chI chO of
                        Nothing -> return Nothing
                        Just chI' -> return $ Just chI'
                _ -> return Nothing
  where
    hpkeHandler :: HPKEError -> IO (Maybe ClientHello)
    hpkeHandler _ = return Nothing
decryptECH _ _ _ _ = return Nothing

fill0ClientHello :: Int -> ClientHello -> ClientHello
fill0ClientHello nenc ch@CH{..} =
    ch{chExtensions = fill0Exts nenc chExtensions}

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

expandClientHello :: ClientHello -> ClientHello -> Maybe ClientHello
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

getHPKE
    :: ServerParams
    -> Context
    -> EncryptedClientHello
    -> IO (Maybe (HPKEF, Int))
getHPKE ServerParams{..} ctx ECHClientHelloOuter{..} = do
    mfunc <- getTLS13HPKE ctx
    case mfunc of
        Nothing -> do
            let mconfig = findECHConfigById echConfigId $ sharedECHConfigList serverShared
                mskR = lookup echConfigId serverECHKey
            case (mconfig, mskR) of
                (Just config, Just skR') -> do
                    let kemid = KEM_ID $ kem_id $ key_config $ contents config
                        skR = EncodedSecretKey skR'
                        encodedConfig = encodeECHConfig config
                    let info = "tls ech\x00" <> encodedConfig
                        (kdfid, aeadid) = echCipherSuite
                    ctxR <- setupBaseR kemid kdfid aeadid skR Nothing echEnc info
                    let nenc = nEnc kemid
                        func = open ctxR
                    setTLS13HPKE ctx func nenc
                    return $ Just (func, nenc)
                _ -> return Nothing
        _ -> return mfunc
getHPKE _ _ _ = return Nothing

findECHConfigById :: ConfigId -> ECHConfigList -> Maybe ECHConfig
findECHConfigById cnfId echConfigList = find eqCfgId echConfigList
  where
    eqCfgId cnf = config_id (key_config (contents cnf)) == cnfId
