{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.QUIC where

import Network.TLS.Handshake.Control
import Network.TLS.Imports

import Control.Concurrent
import qualified Control.Exception as E
import System.Mem.Weak

type ServerController = ServerControl -> IO ServerStatus
type ClientController = ClientControl -> IO ClientStatus

quicServer :: Weak ThreadId
           -> IO ServerStatusI
           -> IO ByteString
           -> ServerController
quicServer _ ask get PutClientHello = do
        rsp <- ask
        case rsp of
          SendRequestRetryI -> SendRequestRetry <$> get
          SendServerHelloI{} -> SendServerHello <$> get
          ServerHandshakeFailedI e -> E.throwIO e
          _ -> error "quicServer"
quicServer _ ask get GetServerFinished = do
    rsp <- ask
    case rsp of
      SendServerFinishedI _ -> SendServerFinished <$> get
      ServerHandshakeFailedI e -> E.throwIO e
      _ -> error "quicServer"
quicServer _ ask get PutClientFinished = do
        rsp <- ask
        case rsp of
          SendSessionTicketI -> SendSessionTicket <$> get
          ServerHandshakeFailedI e -> E.throwIO e
          _ -> error "quicServer"
quicServer wtid _ _ ExitServer = do
    mtid <- deRefWeak wtid
    case mtid of
      Nothing  -> return ()
      Just tid -> killThread tid
    return ServerHandshakeDone

quicClient :: Weak ThreadId
           -> IO ClientStatusI
           -> IO ByteString
           -> ClientController
quicClient _ ask get GetClientHello = do
    rsp <- ask
    case rsp of
      SendClientHelloI _ -> SendClientHello <$> get
      ClientHandshakeFailedI e -> E.throwIO e
      _ -> error "quicClient"
quicClient _ ask get PutServerHello = do
        rsp <- ask
        case rsp of
            SendClientHelloI _ -> SendClientHello <$> get
            RecvServerHelloI _ -> return RecvServerHello
            ClientHandshakeFailedI e -> E.throwIO e
            _ -> error "quicClient"
quicClient _ ask get PutServerFinished = do
        rsp <- ask
        case rsp of
          SendClientFinishedI _ _ -> SendClientFinished <$> get
          ClientHandshakeFailedI e -> E.throwIO e
          _ -> error "quicClient"
quicClient _ ask _ PutSessionTicket = do
        rsp <- ask
        case rsp of
          RecvSessionTicketI -> return RecvSessionTicket
          ClientHandshakeFailedI e -> E.throwIO e
          _ -> error "quicClient"
quicClient wtid _ _ ExitClient = do
    mtid <- deRefWeak wtid
    case mtid of
      Nothing  -> return ()
      Just tid -> killThread tid
    return ClientHandshakeDone
