{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.QUIC where

import Network.TLS.Handshake.Control

import Control.Concurrent
import qualified Control.Exception as E
import System.Mem.Weak

type ServerController = ServerControl -> IO ServerStatus
type ClientController = ClientControl -> IO ClientStatus

quicServer :: Weak ThreadId
           -> IO ServerStatusI
           -> ServerController
quicServer _ ask PutClientHello = do
    rsp <- ask
    case rsp of
      SendServerFinishedI _ -> return SendServerFinished
      ServerHandshakeFailedI e -> E.throwIO e
      _ -> error "quicServer"
quicServer _ ask PutClientFinished = do
        rsp <- ask
        case rsp of
          SendSessionTicketI -> return SendSessionTicket
          ServerHandshakeFailedI e -> E.throwIO e
          _ -> error "quicServer"
quicServer wtid _ ExitServer = do
    mtid <- deRefWeak wtid
    case mtid of
      Nothing  -> return ()
      Just tid -> killThread tid
    return ServerHandshakeDone

quicClient :: Weak ThreadId
           -> IO ClientStatusI
           -> ClientController
quicClient _ ask GetClientHello = do
        rsp <- ask
        case rsp of
          SendClientFinishedI _ _ -> return SendClientFinished
          ClientHandshakeFailedI e -> E.throwIO e
          _ -> error "quicClient"
quicClient _ ask PutSessionTicket = do
        rsp <- ask
        case rsp of
          RecvSessionTicketI -> return RecvSessionTicket
          ClientHandshakeFailedI e -> E.throwIO e
          _ -> error "quicClient"
quicClient wtid _ ExitClient = do
    mtid <- deRefWeak wtid
    case mtid of
      Nothing  -> return ()
      Just tid -> killThread tid
    return ClientHandshakeDone
