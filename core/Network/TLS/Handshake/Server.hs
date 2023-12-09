{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.Server (
    handshakeServer,
    handshakeServerWith,
    requestCertificateServer,
    postHandshakeAuthServerWith,
) where

import Control.Exception (bracket)
import Control.Monad.State.Strict

import Network.TLS.Context.Internal
import Network.TLS.Extension
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.Server.TLS12
import Network.TLS.Handshake.Server.TLS13
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.Measurement
import Network.TLS.Parameters
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types

-- Put the server context in handshake mode.
--
-- Expect to receive as first packet a client hello handshake message
--
-- This is just a helper to pop the next message from the recv layer,
-- and call handshakeServerWith.
handshakeServer :: ServerParams -> Context -> IO ()
handshakeServer sparams ctx = liftIO $ do
    hss <- recvPacketHandshake ctx
    case hss of
        [ch] -> handshakeServerWith sparams ctx ch
        _ -> unexpected (show hss) (Just "client hello")

-- | Put the server context in handshake mode.
--
-- Expect a client hello message as parameter.
-- This is useful when the client hello has been already poped from the recv layer to inspect the packet.
--
-- When the function returns, a new handshake has been succesfully negociated.
-- On any error, a HandshakeFailed exception is raised.
--
-- handshake protocol (<- receiving, -> sending, [] optional):
--    (no session)           (session resumption)
--      <- client hello       <- client hello
--      -> server hello       -> server hello
--      -> [certificate]
--      -> [server key xchg]
--      -> [cert request]
--      -> hello done
--      <- [certificate]
--      <- client key xchg
--      <- [cert verify]
--      <- change cipher      -> change cipher
--      <- finish             -> finish
--      -> change cipher      <- change cipher
--      -> finish             <- finish
handshakeServerWith :: ServerParams -> Context -> Handshake -> IO ()
handshakeServerWith sparams ctx clientHello@(ClientHello legacyVersion _ clientSession ciphers compressions exts _) = do
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
        ( renegotiation && not (supportedClientInitiatedRenegotiation $ ctxSupported ctx)
        )
        $ throwCore
        $ Error_Protocol_Warning "renegotiation is not allowed" NoRenegotiation
    -- check if policy allow this new handshake to happens
    handshakeAuthorized <- withMeasure ctx (onNewHandshake $ serverHooks sparams)
    unless
        handshakeAuthorized
        (throwCore $ Error_HandshakePolicy "server: handshake denied")
    updateMeasure ctx incrementNbHandshakes

    -- Handle Client hello
    processHandshake ctx clientHello

    -- rejecting SSL2. RFC 6176
    when (legacyVersion == SSL2) $
        throwCore $
            Error_Protocol "SSL 2.0 is not supported" ProtocolVersion
    -- rejecting SSL. RFC 7568
    when (legacyVersion == SSL3) $
        throwCore $
            Error_Protocol "SSL 3.0 is not supported" ProtocolVersion

    -- Fallback SCSV: RFC7507
    -- TLS_FALLBACK_SCSV: {0x56, 0x00}
    when
        ( supportedFallbackScsv (ctxSupported ctx)
            && (0x5600 `elem` ciphers)
            && legacyVersion < TLS12
        )
        $ throwCore
        $ Error_Protocol "fallback is not allowed" InappropriateFallback
    -- choosing TLS version
    let clientVersions = case extensionLookup EID_SupportedVersions exts
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
    let serverName = case extensionLookup EID_ServerName exts >>= extensionDecode MsgTClientHello of
            Just (ServerName ns) -> listToMaybe (mapMaybe toHostName ns)
              where
                toHostName (ServerNameHostName hostName) = Just hostName
                toHostName (ServerNameOther _) = Nothing
            _ -> Nothing
    maybe (return ()) (usingState_ ctx . setClientSNI) serverName

    -- TLS version dependent
    if chosenVersion <= TLS12
        then
            handshakeServerWithTLS12
                sparams
                ctx
                chosenVersion
                exts
                ciphers
                serverName
                clientVersion
                compressions
                clientSession
        else do
            mapM_ ensureNullCompression compressions
            -- fixme: we should check if the client random is the same as
            -- that in the first client hello in the case of hello retry.
            handshakeServerWithTLS13
                sparams
                ctx
                chosenVersion
                exts
                ciphers
                serverName
                clientSession
                (handshakeServer sparams ctx) -- for HRR
handshakeServerWith _ _ _ =
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

newCertReqContext :: Context -> IO CertReqContext
newCertReqContext ctx = getStateRNG ctx 32

requestCertificateServer :: ServerParams -> Context -> IO Bool
requestCertificateServer sparams ctx = do
    tls13 <- tls13orLater ctx
    supportsPHA <- usingState_ ctx getClientSupportsPHA
    let ok = tls13 && supportsPHA
    when ok $ do
        certReqCtx <- newCertReqContext ctx
        let certReq = makeCertRequest sparams ctx certReqCtx
        bracket (saveHState ctx) (restoreHState ctx) $ \_ -> do
            addCertRequest13 ctx certReq
            sendPacket13 ctx $ Handshake13 [certReq]
    return ok
