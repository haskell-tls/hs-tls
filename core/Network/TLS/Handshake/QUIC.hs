{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.QUIC where

import Network.TLS.Handshake.Control
import Network.TLS.Imports
import Network.TLS.Struct13

import Control.Concurrent
import qualified Control.Exception as E
import Data.IORef
import System.Mem.Weak

type ServerController = ServerControl -> IO ServerStatus
type ClientController = ClientControl -> IO ClientStatus

quicServer :: Weak ThreadId
           -> IO ServerStatusI
           -> IO ByteString
           -> (ByteString -> IO ())
           -> IORef (Maybe ByteString)
           -> ServerController
quicServer _ ask get put ref (PutClientHello ch) =
    putRecordWith put ref ch HandshakeType_ClientHello13 ServerNeedsMore $ do
        rsp <- ask
        case rsp of
          SendRequestRetryI -> SendRequestRetry <$> get
          SendServerHelloI _ earlySec handSec  -> do
              sh <- get
              return $ SendServerHello sh earlySec handSec
          ServerHandshakeFailedI e -> E.throwIO e
          _ -> error "quicServer"
quicServer _ ask get _ _ GetServerFinished = do
    rsp <- ask
    case rsp of
      SendServerFinishedI appSec -> do
          sf <- get
          return $ SendServerFinished sf appSec
      ServerHandshakeFailedI e -> E.throwIO e
      _ -> error "quicServer"
quicServer _ ask get put ref (PutClientFinished cf) =
    putRecordWith put ref cf HandshakeType_Finished13 ServerNeedsMore $ do
        rsp <- ask
        case rsp of
          SendSessionTicketI -> do
              nst <- get
              return $ SendSessionTicket nst
          ServerHandshakeFailedI e -> E.throwIO e
          _ -> error "quicServer"
quicServer wtid _ _ _ _ ExitServer = do
    mtid <- deRefWeak wtid
    case mtid of
      Nothing  -> return ()
      Just tid -> killThread tid
    return ServerHandshakeDone

quicClient :: Weak ThreadId
           -> IO ClientStatusI
           -> IO ByteString
           -> (ByteString -> IO ())
           -> IORef (Maybe ByteString)
           -> ClientController
quicClient _ ask get _ _ GetClientHello = do
    rsp <- ask
    case rsp of
      SendClientHelloI early -> do
          ch <- get
          return $ SendClientHello ch early
      ClientHandshakeFailedI e -> E.throwIO e
      _ -> error "quicClient"
quicClient _ ask get put ref (PutServerHello sh) =
    putRecordWith put ref sh HandshakeType_ServerHello13 ClientNeedsMore $ do
        rsp <- ask
        case rsp of
            SendClientHelloI early -> do
                ch <- get
                return $ SendClientHello ch early
            RecvServerHelloI handSec -> do
                return $ RecvServerHello handSec
            ClientHandshakeFailedI e -> E.throwIO e
            _ -> error "quicClient"
quicClient _ ask get put ref (PutServerFinished sf) =
    putRecordWith put ref sf HandshakeType_Finished13 ClientNeedsMore $ do
        rsp <- ask
        case rsp of
          SendClientFinishedI _ appSec -> do
              cf <- get
              return $ SendClientFinished cf appSec
          ClientHandshakeFailedI e -> E.throwIO e
          _ -> error "quicClient"
quicClient _ ask _ put ref (PutSessionTicket nst) =
    putRecordWith put ref nst HandshakeType_NewSessionTicket13 ClientNeedsMore $ do
        rsp <- ask
        case rsp of
          RecvSessionTicketI -> return RecvSessionTicket
          ClientHandshakeFailedI e -> E.throwIO e
          _ -> error "quicClient"
quicClient wtid _ _ _ _ ExitClient = do
    mtid <- deRefWeak wtid
    case mtid of
      Nothing  -> return ()
      Just tid -> killThread tid
    return ClientHandshakeDone
