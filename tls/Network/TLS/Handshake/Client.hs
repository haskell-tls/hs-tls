{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.TLS.Handshake.Client (
    handshakeClient,
    handshakeClientWith,
    postHandshakeAuthClientWith,
) where

import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Client.ClientHello
import Network.TLS.Handshake.Client.Common
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

handshakeClientWith
    :: ClientParams -> Context -> HandshakeR -> IO ()
handshakeClientWith cparams ctx (HelloRequest, _b) = handshakeClient cparams ctx -- xxx
handshakeClientWith _ _ _ =
    throwCore $
        Error_Protocol
            "unexpected handshake message received in handshakeClientWith"
            HandshakeFailure

-- client part of handshake. send a bunch of handshake of client
-- values intertwined with response from the server.
handshakeClient :: ClientParams -> Context -> IO ()
handshakeClient cparams ctx = do
    grps <- case clientSessions cparams of
        [] ->
            return $
                Groups
                    { grpsSupported = groupsSupported
                    , grpsSelected = groupsSelected
                    }
        (_, sdata) : _ -> case sessionGroup sdata of
            Nothing ->
                -- TLS 1.2 or earlier
                return $
                    Groups
                        { grpsSupported = groupsSupported -- for ciphers
                        , grpsSelected = []
                        }
            Just grp
                | grp `elem` groupsSupported -> do
                    let supported = grp : filter (/= grp) groupsSupported
                    return $
                        Groups
                            { grpsSupported = supported
                            , grpsSelected = [grp]
                            }
                | otherwise -> throwCore $ Error_Misc "groupsSupported is incorrect"
    handshake cparams ctx grps Nothing
  where
    groupsSupported = supportedGroups (ctxSupported ctx)
    groupsSelected = onSelectKeyShareGroups (clientHooks cparams) groupsSupported

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
    -> Groups
    -> Maybe (ClientRandom, Session, Version)
    -> IO ()
handshake cparams ctx grps@Groups{..} mparams = do
    --------------------------------
    -- Sending ClientHello
    pskinfo@(_, _, rtt0) <- getPreSharedKeyInfo cparams ctx
    when rtt0 $ modifyTLS13State ctx $ \st -> st{tls13st0RTT = True}
    let async = rtt0 && not (ctxQUICMode ctx)
    when async $ do
        chSentTime <- getCurrentTimeFromBase
        asyncServerHello13 cparams ctx grpsSelected chSentTime
    updateMeasure ctx incrementNbHandshakes
    crand <-
        sendClientHello cparams ctx grps mparams pskinfo
    --------------------------------
    -- Receiving ServerHello
    unless async $ do
        (ver, hbs, hrr) <- receiveServerHello cparams ctx mparams
        -- Switching to HRR, TLS 1.2 or TLS 1.3
        case ver of
            TLS13
                | hrr ->
                    helloRetry cparams ctx mparams ver crand (grpsSupported \\ grpsSelected)
                | otherwise -> do
                    recvServerSecondFlight13 cparams ctx grpsSelected
                    sendClientSecondFlight13 cparams ctx
            _
                | rtt0 ->
                    throwCore $
                        Error_Protocol
                            "server denied TLS 1.3 when connecting with early data"
                            HandshakeFailure
                | otherwise -> do
                    recvServerFirstFlight12 cparams ctx hbs
                    sendClientSecondFlight12 cparams ctx
                    recvServerSecondFlight12 cparams ctx

----------------------------------------------------------------

helloRetry
    :: ClientParams
    -> Context
    -> Maybe a
    -> Version
    -> ClientRandom
    -> [Group]
    -> IO ()
helloRetry cparams ctx mparams ver crand groupsSupported = do
    when (null groupsSupported) $
        throwCore $
            Error_Protocol "no supported groups on the client side" IllegalParameter
    when (isJust mparams) $
        throwCore $
            Error_Protocol "server sent too many hello retries" UnexpectedMessage
    mks <- usingState_ ctx getTLS13KeyShare
    case mks of
        Just (KeyShareHRR selectedGroup)
            | selectedGroup `elem` groupsSupported -> do
                usingHState ctx $ setTLS13HandshakeMode HelloRetryRequest
                clearTxRecordState ctx
                let cparams' = cparams{clientUseEarlyData = False}
                runPacketFlight ctx $ sendChangeCipherSpec13 ctx
                clientSession <- tls13stSession <$> getTLS13State ctx
                let groupsSupported' = selectedGroup : filter (/= selectedGroup) groupsSupported
                    groupsSelected' = [selectedGroup]
                    grps =
                        Groups
                            { grpsSupported = groupsSupported'
                            , grpsSelected = groupsSelected'
                            }

                handshake
                    cparams'
                    ctx
                    grps
                    (Just (crand, clientSession, ver))
            | otherwise ->
                throwCore $
                    Error_Protocol "server-selected group is not supported" IllegalParameter
        Just _ -> error "handshake: invalid KeyShare value"
        Nothing ->
            throwCore $
                Error_Protocol
                    "key exchange not implemented in HRR, expected key_share extension"
                    HandshakeFailure
