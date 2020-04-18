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
    , EarlySecretInfo(..)
    , HandshakeSecretInfo(..)
    , ApplicationSecretInfo(..)
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
    , QuicSecretEvent(..)
    , QuicCallbacks(..)
    , NegotiatedProtocol
    , ClientHello
    , ServerHello
    , Finished
    , SessionTicket
    , HandshakeMode13(..)
    , errorToAlertDescription
    , fromAlertDescription
    , toAlertDescription
    , quicMaxEarlyDataSize
    ) where

import Network.TLS.Backend
import Network.TLS.Context
import Network.TLS.Context.Internal
import Network.TLS.Core
import Network.TLS.Crypto (hashDigestSize)
import Network.TLS.Extension (extensionID_QuicTransportParameters)
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Control
import Network.TLS.Handshake.Server
import Network.TLS.Handshake.QUIC
import Network.TLS.Handshake.State
import Network.TLS.Imports
import Network.TLS.KeySchedule (hkdfExtract, hkdfExpandLabel)
import Network.TLS.Record.Layer
import Network.TLS.Struct
import Network.TLS.Types

import Control.Concurrent
import qualified Control.Exception as E
import Data.IORef

nullBackend :: Backend
nullBackend = Backend {
    backendFlush = return ()
  , backendClose = return ()
  , backendSend  = \_ -> return ()
  , backendRecv  = \_ -> return ""
  }

data QuicSecretEvent
    = SyncEarlySecret (Maybe EarlySecretInfo)
    | SyncHandshakeSecret HandshakeSecretInfo
    | SyncApplicationSecret ApplicationSecretInfo

data QuicCallbacks = QuicCallbacks
    { quicNotifySecretEvent :: QuicSecretEvent -> IO ()
    , quicNotifyExtensions  :: [ExtensionRaw] -> IO ()
    }

prepare :: (a -> IO ())
        -> IO (IO ByteString
              ,ByteString -> IO ()
              ,a -> IO ()
              ,IO a
              ,RecordLayer ByteString
              ,IORef (Maybe ByteString))
prepare processI = do
    c1 <- newChan
    c2 <- newChan
    mvar <- newEmptyMVar
    ref <- newIORef Nothing
    let send = writeChan c1
        get  = readChan  c1
        recv = readChan  c2
        put  = writeChan c2
        sync a = processI a >> putMVar mvar a
        ask  = takeMVar mvar
        rl   =  newTransparentRecordLayer send recv
    return (get, put, sync, ask, rl, ref)

newQUICClient :: ClientParams -> QuicCallbacks -> IO ClientController
newQUICClient cparams callbacks = do
    (get, put, sync, ask, rl, ref) <- prepare processI
    ctx <- contextNew nullBackend cparams
    let ctx' = updateRecordLayer rl ctx
          { ctxHandshakeSync = HandshakeSync sync (\_ -> return ())
          }
        failed = sync . ClientHandshakeFailedI
    tid <- forkIO $ E.handle failed $ do
        handshake ctx'
        void $ recvData ctx'
    wtid <- mkWeakThreadId tid
    return (quicClient wtid ask get put ref)

  where
    processI (SendClientHelloI mEarlySecInfo) =
        quicNotifySecretEvent callbacks (SyncEarlySecret mEarlySecInfo)
    processI (RecvServerHelloI handSecInfo) =
        quicNotifySecretEvent callbacks (SyncHandshakeSecret handSecInfo)
    processI (SendClientFinishedI exts appSecInfo) = do
        quicNotifySecretEvent callbacks (SyncApplicationSecret appSecInfo)
        let exts' = filter (\(ExtensionRaw eid _) -> eid == extensionID_QuicTransportParameters) exts
        quicNotifyExtensions callbacks exts'
    processI _ = return ()

newQUICServer :: ServerParams -> QuicCallbacks -> IO ServerController
newQUICServer sparams callbacks = do
    (get, put, sync, ask, rl, ref) <- prepare processI
    ctx <- contextNew nullBackend sparams
    let ctx' = updateRecordLayer rl ctx
          { ctxHandshakeSync = HandshakeSync (\_ -> return ()) sync
          }
        failed = sync . ServerHandshakeFailedI
    tid <- forkIO $ E.handle failed $ do
        handshake ctx'
        void $ recvData ctx'
    wtid <- mkWeakThreadId tid
    return (quicServer wtid ask get put ref)

  where
    processI (SendServerHelloI exts mEarlySecInfo handSecInfo) = do
        quicNotifySecretEvent callbacks (SyncEarlySecret mEarlySecInfo)
        quicNotifySecretEvent callbacks (SyncHandshakeSecret handSecInfo)
        let exts' = filter (\(ExtensionRaw eid _) -> eid == extensionID_QuicTransportParameters) exts
        quicNotifyExtensions callbacks exts'
    processI (SendServerFinishedI appSecInfo) =
        quicNotifySecretEvent callbacks (SyncApplicationSecret appSecInfo)
    processI _ = return ()

errorToAlertDescription :: TLSError -> AlertDescription
errorToAlertDescription = snd . head . errorToAlert

fromAlertDescription :: AlertDescription -> Word8
fromAlertDescription = valOfType

toAlertDescription :: Word8 -> Maybe AlertDescription
toAlertDescription = valToType
