{-# LANGUAGE RecordWildCards #-}

module Network.TLS.Handshake.Server.ClientHello (
    processClientHello,
) where

import Network.TLS.Compression
import Network.TLS.Context.Internal
import Network.TLS.Extension
import Network.TLS.Handshake.Process
import Network.TLS.Imports
import Network.TLS.Measurement
import Network.TLS.Parameters
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Types

processClientHello
    :: ServerParams -> Context -> Handshake -> IO (Version, CH)
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

    -- Handle Client hello
    hrr <- usingState_ ctx getTLS13HRR
    unless hrr $ startHandshake ctx legacyVersion cran
    processHandshake12 ctx clientHello

    when (legacyVersion /= TLS12) $
        throwCore $
            Error_Protocol (show legacyVersion ++ " is not supported") ProtocolVersion

    -- Fallback SCSV: RFC7507
    -- TLS_FALLBACK_SCSV: {0x56, 0x00}
    when
        ( supportedFallbackScsv (ctxSupported ctx)
            && (CipherID 0x5600 `elem` chCiphers)
            && legacyVersion < TLS12
        )
        $ throwCore
        $ Error_Protocol "fallback is not allowed" InappropriateFallback
    -- choosing TLS version
    let clientVersions = case extensionLookup EID_SupportedVersions chExtensions
            >>= extensionDecode MsgTClientHello of
            Just (SupportedVersionsClientHello vers) -> vers -- fixme: vers == []
            _ -> []
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

    -- SNI (Server Name Indication)
    let serverName = case extensionLookup EID_ServerName chExtensions >>= extensionDecode MsgTClientHello of
            Just (ServerName ns) -> listToMaybe (mapMaybe toHostName ns)
              where
                toHostName (ServerNameHostName hostName) = Just hostName
                toHostName (ServerNameOther _) = Nothing
            _ -> Nothing
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
    maybe (return ()) (usingState_ ctx . setClientSNI) serverName
    return (chosenVersion, ch)
processClientHello _ _ _ =
    throwCore $
        Error_Protocol
            "unexpected handshake message received in handshakeServerWith"
            HandshakeFailure

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
