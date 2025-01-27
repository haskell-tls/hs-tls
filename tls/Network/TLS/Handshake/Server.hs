{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.Server (
    handshakeServer,
    handshakeServerWith,
    requestCertificateServer,
) where

import Control.Monad.State.Strict

import Network.TLS.Context.Internal
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Server.ClientHello
import Network.TLS.Handshake.Server.ClientHello12
import Network.TLS.Handshake.Server.ClientHello13
import Network.TLS.Handshake.Server.ServerHello12
import Network.TLS.Handshake.Server.ServerHello13
import Network.TLS.Handshake.Server.TLS12
import Network.TLS.Handshake.Server.TLS13
import Network.TLS.Struct

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
        [ch] -> handshake sparams ctx ch
        _ -> unexpected (show hss) (Just "client hello")

handshakeServerWith :: ServerParams -> Context -> Handshake -> IO ()
handshakeServerWith = handshake

-- | Put the server context in handshake mode.
--
-- Expect a client hello message as parameter.
-- This is useful when the client hello has been already poped from the recv layer to inspect the packet.
--
-- When the function returns, a new handshake has been succesfully negociated.
-- On any error, a HandshakeFailed exception is raised.
handshake :: ServerParams -> Context -> Handshake -> IO ()
handshake sparams ctx clientHello = do
    (chosenVersion, ch) <- processClientHello sparams ctx clientHello
    if chosenVersion == TLS13
        then do
            -- fixme: we should check if the client random is the same as
            -- that in the first client hello in the case of hello retry.
            (mClientKeyShare, r0) <-
                processClientHello13 sparams ctx ch
            case mClientKeyShare of
                Nothing -> do
                    sendHRR ctx r0 ch
                    -- Don't reset ctxEstablished since 0-RTT data
                    -- would be comming, which should be ignored.
                    handshakeServer sparams ctx
                Just cliKeyShare -> do
                    r1 <-
                        sendServerHello13 sparams ctx cliKeyShare r0 ch
                    recvClientSecondFlight13 sparams ctx r1 ch
        else do
            r <-
                processClientHello12 sparams ctx ch
            resumeSessionData <-
                sendServerHello12 sparams ctx r ch
            recvClientSecondFlight12 sparams ctx resumeSessionData
