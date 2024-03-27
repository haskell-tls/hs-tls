{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.Client.ServerHello (
    recvServerHello,
    processServerHello13,
) where

import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Context.Internal
import Network.TLS.ErrT
import Network.TLS.Extension
import Network.TLS.Handshake.Client.Common
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.Random
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.Parameters
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types

----------------------------------------------------------------

recvServerHello
    :: ClientParams -> Context -> IO [Handshake]
recvServerHello cparams ctx = do
    (sh, hss) <- recvSH
    processServerHello cparams ctx sh
    processHandshake12 ctx sh
    return hss
  where
    recvSH = do
        epkt <- recvPacket12 ctx
        case epkt of
            Left e -> throwCore e
            Right pkt -> case pkt of
                Alert a -> throwAlert a
                Handshake (h : hs) -> return (h, hs)
                _ -> unexpected (show pkt) (Just "handshake")
    throwAlert a =
        throwCore $
            Error_Protocol
                ("expecting server hello, got alert : " ++ show a)
                HandshakeFailure

----------------------------------------------------------------

processServerHello13
    :: ClientParams -> Context -> Handshake13 -> IO ()
processServerHello13 cparams ctx (ServerHello13 serverRan serverSession cipher exts) = do
    let sh = ServerHello TLS12 serverRan serverSession cipher 0 exts
    processServerHello cparams ctx sh
processServerHello13 _ _ h = unexpected (show h) (Just "server hello")

-- | processServerHello processes the ServerHello message on the client.
--
-- 1) check the version chosen by the server is one allowed by parameters.
-- 2) check that our compression and cipher algorithms are part of the list we sent
-- 3) check extensions received are part of the one we sent
-- 4) process the session parameter to see if the server want to start a new session or can resume
processServerHello
    :: ClientParams -> Context -> Handshake -> IO ()
processServerHello cparams ctx (ServerHello rver serverRan serverSession cipher compression exts) = do
    -- A server which receives a legacy_version value not equal to
    -- 0x0303 MUST abort the handshake with an "illegal_parameter"
    -- alert.
    when (rver /= TLS12) $
        throwCore $
            Error_Protocol (show rver ++ " is not supported") IllegalParameter
    -- find the compression and cipher methods that the server want to use.
    clientSession <- tls13stSession <$> getTLS13State ctx
    sentExts <- tls13stSentExtensions <$> getTLS13State ctx
    cipherAlg <- case find ((==) cipher . cipherID) (supportedCiphers $ ctxSupported ctx) of
        Nothing -> throwCore $ Error_Protocol "server choose unknown cipher" IllegalParameter
        Just alg -> return alg
    compressAlg <- case find
        ((==) compression . compressionID)
        (supportedCompressions $ ctxSupported ctx) of
        Nothing ->
            throwCore $ Error_Protocol "server choose unknown compression" IllegalParameter
        Just alg -> return alg
    ensureNullCompression compression

    -- intersect sent extensions in client and the received extensions from server.
    -- if server returns extensions that we didn't request, fail.
    let checkExt (ExtensionRaw i _)
            | i == EID_Cookie = False -- for HRR
            | otherwise = i `notElem` sentExts
    when (any checkExt exts) $
        throwCore $
            Error_Protocol "spurious extensions received" UnsupportedExtension

    let isHRR = isHelloRetryRequest serverRan
    usingState_ ctx $ do
        setTLS13HRR isHRR
        setTLS13Cookie
            ( guard isHRR
                >> extensionLookup EID_Cookie exts
                >>= extensionDecode MsgTServerHello
            )
        setVersion rver -- must be before processing supportedVersions ext
        mapM_ processServerExtension exts

    setALPN ctx MsgTServerHello exts

    ver <- usingState_ ctx getVersion

    when (ver == TLS12) $ do
        usingHState ctx $ setServerHelloParameters rver serverRan cipherAlg compressAlg

    let supportedVers = supportedVersions $ clientSupported cparams

    when (ver == TLS13) $ do
        when (clientSession /= serverSession) $
            throwCore $
                Error_Protocol
                    "session is not matched in compatibility mode"
                    IllegalParameter
        when (ver `notElem` supportedVers) $
            throwCore $
                Error_Protocol
                    ("server version " ++ show ver ++ " is not supported")
                    ProtocolVersion

    -- Some servers set TLS 1.2 as the legacy server hello version, and TLS 1.3
    -- in the supported_versions extension, *AND ALSO* set the TLS 1.2
    -- downgrade signal in the server random.  If we support TLS 1.3 and
    -- actually negotiate TLS 1.3, we must ignore the server random downgrade
    -- signal.  Therefore, 'isDowngraded' needs to take into account the
    -- negotiated version and the server random, as well as the list of
    -- client-side enabled protocol versions.
    --
    when (isDowngraded ver supportedVers serverRan) $
        throwCore $
            Error_Protocol "version downgrade detected" IllegalParameter

    let resumingSession =
            case clientWantSessionResume cparams of
                Just (_, sessionData) ->
                    if serverSession == clientSession then Just sessionData else Nothing
                Nothing -> Nothing
    usingState_ ctx $ setSession serverSession (isJust resumingSession)

    if ver == TLS13
        then updateContext13 ctx cipherAlg
        else updateContext12 ctx exts resumingSession
processServerHello _ _ p = unexpected (show p) (Just "server hello")

----------------------------------------------------------------

processServerExtension :: ExtensionRaw -> TLSSt ()
processServerExtension (ExtensionRaw extID content)
    | extID == EID_SecureRenegotiation = do
        cvd <- getVerifyData ClientRole
        svd <- getVerifyData ServerRole
        let bs = extensionEncode $ SecureRenegotiation cvd svd
        unless (bs == content) $
            throwError $
                Error_Protocol "server secure renegotiation data not matching" HandshakeFailure
    | extID == EID_SupportedVersions = case extensionDecode MsgTServerHello content of
        Just (SupportedVersionsServerHello ver) -> setVersion ver
        _ -> return ()
    | extID == EID_KeyShare = do
        hrr <- getTLS13HRR
        let msgt = if hrr then MsgTHelloRetryRequest else MsgTServerHello
        setTLS13KeyShare $ extensionDecode msgt content
    | extID == EID_PreSharedKey =
        setTLS13PreSharedKey $ extensionDecode MsgTServerHello content
    | extID == EID_SessionTicket = setTLS12SessionTicket "" -- empty ticket
processServerExtension _ = return ()

----------------------------------------------------------------

updateContext13 :: Context -> Cipher -> IO ()
updateContext13 ctx cipherAlg = do
    established <- ctxEstablished ctx
    eof <- ctxEOF ctx
    when (established == Established && not eof) $
        throwCore $
            Error_Protocol
                "renegotiation to TLS 1.3 or later is not allowed"
                ProtocolVersion
    failOnEitherError $ usingHState ctx $ setHelloParameters13 cipherAlg

updateContext12 :: Context -> [ExtensionRaw] -> Maybe SessionData -> IO ()
updateContext12 ctx exts resumingSession = do
    ems <- processExtendedMainSecret ctx TLS12 MsgTServerHello exts
    case resumingSession of
        Nothing -> return ()
        Just sessionData -> do
            let emsSession = SessionEMS `elem` sessionFlags sessionData
            when (ems /= emsSession) $
                let err = "server resumes a session which is not EMS consistent"
                 in throwCore $ Error_Protocol err HandshakeFailure
            let mainSecret = sessionSecret sessionData
            usingHState ctx $ setMainSecret TLS12 ClientRole mainSecret
            logKey ctx (MainSecret mainSecret)
