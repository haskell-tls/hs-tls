{-# LANGUAGE DeriveDataTypeable, OverloadedStrings #-}
-- |
-- Module      : Network.TLS.Handshake
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake
    ( handshake
    , handshakeServerWith
    , handshakeClient
    , HandshakeFailed(..)
    ) where

import Network.TLS.Context
import Network.TLS.Struct
import Network.TLS.IO

import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Client
import Network.TLS.Handshake.Server

import Control.Monad.State
import Control.Exception (fromException)
import qualified Control.Exception as E

-- | Handshake for a new TLS connection
-- This is to be called at the beginning of a connection, and during renegotiation
handshake :: MonadIO m => Context -> m ()
handshake ctx = do
    let handshakeF = case roleParams $ ctxParams ctx of
                        Server sparams -> handshakeServer sparams
                        Client cparams -> handshakeClient cparams
    liftIO $ handleException $ handshakeF ctx
  where handleException f = E.catch f $ \exception -> do
            let tlserror = maybe (Error_Misc $ show exception) id $ fromException exception
            setEstablished ctx False
            sendPacket ctx (errorToAlert tlserror)
            handshakeFailed tlserror
