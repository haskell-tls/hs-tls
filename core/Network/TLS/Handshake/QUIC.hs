{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.QUIC where

import Network.TLS.Handshake.Control
import Network.TLS.Imports

import Control.Concurrent
import System.Mem.Weak

type ServerController = ServerControl -> IO ServerStatus
type ClientController = ClientControl -> IO ClientStatus

quicServer :: Weak ThreadId
           -> IO ServerStatus
           -> ServerController
quicServer wtid _ ExitServer = do
    mtid <- deRefWeak wtid
    forM_ mtid killThread
    return ServerHandshakeDone
quicServer _ ask _ = ask

quicClient :: Weak ThreadId
           -> IO ClientStatus
           -> ClientController
quicClient wtid _ ExitClient = do
    mtid <- deRefWeak wtid
    forM_ mtid killThread
    return ClientHandshakeDone
quicClient _ ask _ = ask
