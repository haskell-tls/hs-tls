{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.Client (
    handshakeClient,
    handshakeClientWith,
    postHandshakeAuthClientWith,
) where

import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Client.ClientHello
import Network.TLS.Handshake.Client.ServerHello
import Network.TLS.Handshake.Client.TLS12
import Network.TLS.Handshake.Client.TLS13
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.Measurement
import Network.TLS.Parameters
import Network.TLS.State
import Network.TLS.Struct

----------------------------------------------------------------

handshakeClientWith :: ClientParams -> Context -> Handshake -> IO ()
handshakeClientWith cparams ctx HelloRequest = handshakeClient cparams ctx
handshakeClientWith _ _ _ =
    throwCore $
        Error_Protocol
            "unexpected handshake message received in handshakeClientWith"
            HandshakeFailure

-- client part of handshake. send a bunch of handshake of client
-- values intertwined with response from the server.
handshakeClient :: ClientParams -> Context -> IO ()
handshakeClient cparams ctx = handshake cparams ctx groups Nothing
  where
    groupsSupported = supportedGroups (ctxSupported ctx)
    groups = case clientWantSessionResume cparams of
        Nothing -> groupsSupported
        Just (_, sdata) -> case sessionGroup sdata of
            Nothing -> [] -- TLS 1.2 or earlier
            Just grp -> grp : filter (/= grp) groupsSupported

-- https://tools.ietf.org/html/rfc8446#section-4.1.2 says:
-- "The client will also send a
--  ClientHello when the server has responded to its ClientHello with a
--  HelloRetryRequest.  In that case, the client MUST send the same
--  ClientHello without modification, except as follows:"
--
-- So, the ClientRandom in the first client hello is necessary.
handshake
    :: ClientParams
    -> Context
    -> [Group]
    -> Maybe (ClientRandom, Session, Version)
    -> IO ()
handshake cparams ctx groups mparams = do
    --------------------------------
    -- Sending ClientHello
    pskinfo@(_, _, rtt0) <- getPreSharedKeyInfo cparams ctx
    when rtt0 $ modifyTLS13State ctx $ \st -> st{tls13st0RTT = True}
    let async = rtt0 && not (ctxQUICMode ctx)
    when async $ do
        chSentTime <- getCurrentTimeFromBase
        asyncServerHello13 cparams ctx groupToSend chSentTime
    updateMeasure ctx incrementNbHandshakes
    crand <- sendClientHello cparams ctx groups mparams pskinfo
    --------------------------------
    -- Receiving ServerHello
    unless async $ do
        (ver, hss, hrr) <- receiveServerHello cparams ctx mparams
        --------------------------------
        -- Switching to HRR, TLS 1.2 or TLS 1.3
        case ver of
            TLS13
                | hrr ->
                    helloRetry cparams ctx mparams ver crand $ drop 1 groups
                | otherwise -> do
                    recvServerSecondFlight13 cparams ctx groupToSend
                    sendClientSecondFlight13 cparams ctx
            _
                | rtt0 ->
                    throwCore $
                        Error_Protocol
                            "server denied TLS 1.3 when connecting with early data"
                            HandshakeFailure
                | otherwise -> do
                    recvServerFirstFlight12 cparams ctx hss
                    sendClientSecondFlight12 cparams ctx
                    recvServerSecondFlight12 ctx
  where
    groupToSend = listToMaybe groups

receiveServerHello
    :: ClientParams
    -> Context
    -> Maybe (ClientRandom, Session, Version)
    -> IO (Version, [Handshake], Bool)
receiveServerHello cparams ctx mparams = do
    chSentTime <- getCurrentTimeFromBase
    hss <- recvServerHello cparams ctx
    setRTT ctx chSentTime
    ver <- usingState_ ctx getVersion
    unless (maybe True (\(_, _, v) -> v == ver) mparams) $
        throwCore $
            Error_Protocol "version changed after hello retry" IllegalParameter
    -- recvServerHello sets TLS13HRR according to the server random.
    -- For 1st server hello, getTLS13HR returns True if it is HRR and
    -- False otherwise.  For 2nd server hello, getTLS13HR returns
    -- False since it is NOT HRR.
    hrr <- usingState_ ctx getTLS13HRR
    return (ver, hss, hrr)

----------------------------------------------------------------

helloRetry
    :: ClientParams
    -> Context
    -> Maybe a
    -> Version
    -> ClientRandom
    -> [Group]
    -> IO ()
helloRetry cparams ctx mparams ver crand groups = do
    when (null groups) $
        throwCore $
            Error_Protocol "group is exhausted in the client side" IllegalParameter
    when (isJust mparams) $
        throwCore $
            Error_Protocol "server sent too many hello retries" UnexpectedMessage
    mks <- usingState_ ctx getTLS13KeyShare
    case mks of
        Just (KeyShareHRR selectedGroup)
            | selectedGroup `elem` groups -> do
                usingHState ctx $ setTLS13HandshakeMode HelloRetryRequest
                clearTxRecordState ctx
                let cparams' = cparams{clientUseEarlyData = False}
                runPacketFlight ctx $ sendChangeCipherSpec13 ctx
                clientSession <- tls13stSession <$> getTLS13State ctx
                handshake cparams' ctx [selectedGroup] (Just (crand, clientSession, ver))
            | otherwise ->
                throwCore $
                    Error_Protocol "server-selected group is not supported" IllegalParameter
        Just _ -> error "handshake: invalid KeyShare value"
        Nothing ->
            throwCore $
                Error_Protocol
                    "key exchange not implemented in HRR, expected key_share extension"
                    HandshakeFailure
