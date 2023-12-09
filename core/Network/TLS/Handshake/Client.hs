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

{- FOURMOLU_DISABLE -}
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
    updateMeasure ctx incrementNbHandshakes
    (crand, clientSession, rtt0, sentExtensions) <-
        sendClientHello cparams ctx groups mparams
    hss <- recvServerHello ctx cparams clientSession sentExtensions
    ver <- usingState_ ctx getVersion
    unless (maybe True (\(_, _, v) -> v == ver) mparams) $
        throwCore $
            Error_Protocol "version changed after hello retry" IllegalParameter
    -- recvServerHello sets TLS13HRR according to the server random.
    -- For 1st server hello, getTLS13HR returns True if it is HRR and
    -- False otherwise.  For 2nd server hello, getTLS13HR returns
    -- False since it is NOT HRR.
    hrr <- usingState_ ctx getTLS13HRR
    case ver of
        TLS13
            | hrr       -> helloRetry cparams ctx mparams ver crand clientSession $ drop 1 groups
            | otherwise -> do
                  r <- recvServerSecondFlight13 cparams ctx groupToSend
                  sendClientSecondFlight13 cparams ctx r
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
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

helloRetry
    :: ClientParams
    -> Context
    -> Maybe a
    -> Version
    -> ClientRandom
    -> Session
    -> [Group]
    -> IO ()
helloRetry cparams ctx mparams ver crand clientSession groups = do
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
                clearTxState ctx
                let cparams' = cparams{clientEarlyData = Nothing}
                runPacketFlight ctx $ sendChangeCipherSpec13 ctx
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
