{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.QUIC where

import Network.TLS.Handshake.Control

import Control.Concurrent
import System.Mem.Weak

type ServerController = ServerControl -> IO ServerStatus
type ClientController = ClientControl -> IO ClientStatus

quicServer :: Weak ThreadId
           -> IO ServerStatus
           -> ServerController
quicServer wtid _ ExitServer = do
    mtid <- deRefWeak wtid
    case mtid of
      Nothing  -> return ()
      Just tid -> killThread tid
    return ServerHandshakeDone
quicServer _ ask _ = ask

quicClient :: Weak ThreadId
           -> IO ClientStatus
           -> ClientController
quicClient wtid _ ExitClient = do
    mtid <- deRefWeak wtid
    case mtid of
      Nothing  -> return ()
      Just tid -> killThread tid
    return ClientHandshakeDone
quicClient _ ask _ = ask
