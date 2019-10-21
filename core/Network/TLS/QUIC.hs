{-# LANGUAGE OverloadedStrings #-}
module Network.TLS.QUIC (
    -- * Hash
      hkdfExpandLabel
    , hkdfExtract
    , hashDigestSize
    -- * Extensions
    , ExtensionRaw(..)
    , ExtensionID
    , extensionID_QuicTransportParameters
    -- * Secrets
    , ServerTrafficSecret(..)
    , ClientTrafficSecret(..)
    , EarlySecret
    , HandshakeSecret
    , ApplicationSecret
    , TrafficSecrets
    -- * Client handshake controller
    , newQUICClient
    , ClientController
    , ClientControl(..)
    , ClientStatus(..)
    -- * Server handshake controller
    , newQUICServer
    , ServerController
    , ServerControl(..)
    , ServerStatus(..)
    -- * Common
    , NegotiatedProtocol
    , ClientHello
    , ServerHello
    , Finished
    , SessionTicket
    ) where

import Network.TLS.Backend
import Network.TLS.Context
import Network.TLS.Context.Internal
import Network.TLS.Core
import Network.TLS.Crypto (hashDigestSize)
import Network.TLS.Extension (extensionID_QuicTransportParameters)
import Network.TLS.Handshake.Control
import Network.TLS.Handshake.QUIC
import Network.TLS.Imports
import Network.TLS.KeySchedule (hkdfExtract, hkdfExpandLabel)
import Network.TLS.Record.Layer
import Network.TLS.Struct (ExtensionRaw(..), ExtensionID)
import Network.TLS.Types

import Control.Concurrent
import Data.IORef

nullBackend :: Backend
nullBackend = Backend {
    backendFlush = return ()
  , backendClose = return ()
  , backendSend  = \_ -> return ()
  , backendRecv  = \_ -> return ""
  }

prepare :: IO (IO ByteString
              ,ByteString -> IO ()
              ,a -> IO ()
              ,IO a
              ,RecordLayer
              ,IORef (Maybe ByteString))
prepare = do
    c1 <- newChan
    c2 <- newChan
    mvar <- newEmptyMVar
    ref <- newIORef Nothing
    let send = writeChan c1
        get  = readChan  c1
        recv = readChan  c2
        put  = writeChan c2
        sync = putMVar mvar
        ask  = takeMVar mvar
        rl   =  newTransparentRecordLayer send recv
    return (get, put, sync, ask, rl, ref)

newQUICClient :: ClientParams -> IO ClientController
newQUICClient cparams = do
    (get, put, sync, ask, rl, ref) <- prepare
    ctx <- contextNew nullBackend cparams
    let ctx' = ctx {
            ctxRecordLayer   = Just rl
          , ctxHandshakeSync = Just (HandshakeSync sync (\_ -> return ()))
          }
    tid <- forkIO $ do
        handshake ctx'
        void $ recvData ctx'
    return (quicClient tid ask get put ref)

newQUICServer :: ServerParams -> IO ServerController
newQUICServer sparams = do
    (get, put, sync, ask, rl, ref) <- prepare
    ctx <- contextNew nullBackend sparams
    let ctx' = ctx {
            ctxRecordLayer   = Just rl
          , ctxHandshakeSync = Just (HandshakeSync (\_ -> return ()) sync)
          }
    tid <- forkIO $ do
        handshake ctx'
        void $ recvData ctx'
    return (quicServer tid ask get put ref)
