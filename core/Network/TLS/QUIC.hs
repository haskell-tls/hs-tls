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
    , CryptLevel(..)
    , KeyScheduleEvent(..)
    , QUICCallbacks(..)
    , NegotiatedProtocol
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
import Network.TLS.Handshake.State13
import Network.TLS.Imports
import Network.TLS.KeySchedule (hkdfExtract, hkdfExpandLabel)
import Network.TLS.Record.Layer
import Network.TLS.Record.State
import Network.TLS.Struct
import Network.TLS.Types

import Control.Concurrent
import qualified Control.Exception as E

nullBackend :: Backend
nullBackend = Backend {
    backendFlush = return ()
  , backendClose = return ()
  , backendSend  = \_ -> return ()
  , backendRecv  = \_ -> return ""
  }

data KeyScheduleEvent
    = InstallEarlyKeys (Maybe EarlySecretInfo)
    | InstallHandshakeKeys HandshakeSecretInfo
    | InstallApplicationKeys ApplicationSecretInfo

data QUICCallbacks = QUICCallbacks
    { quicSend              :: [(CryptLevel, ByteString)] -> IO ()
    , quicRecv              :: CryptLevel -> IO ByteString
    , quicInstallKeys       :: KeyScheduleEvent -> IO ()
    , quicNotifyExtensions  :: [ExtensionRaw] -> IO ()
    }

getTxLevel :: Context -> IO CryptLevel
getTxLevel ctx = do
    (_, _, level, _) <- getTxState ctx
    return level

getRxLevel :: Context -> IO CryptLevel
getRxLevel ctx = do
    (_, _, level, _) <- getRxState ctx
    return level

prepare :: ((status -> IO ()) -> statusI -> IO ())
        -> IO (statusI -> IO (), IO status)
prepare processI = do
    mvar <- newEmptyMVar
    let sync a = let put = putMVar mvar in processI put a
        ask  = takeMVar mvar
    return (sync, ask)

newRecordLayer :: Context -> QUICCallbacks
               -> RecordLayer [(CryptLevel, ByteString)]
newRecordLayer ctx callbacks = newTransparentRecordLayer get send recv
  where
    get     = getTxLevel ctx
    send    = quicSend callbacks
    recv    = getRxLevel ctx >>= quicRecv callbacks

newQUICClient :: ClientParams -> QUICCallbacks -> IO ClientController
newQUICClient cparams callbacks = do
    (sync, ask) <- prepare processI
    ctx <- contextNew nullBackend cparams
    let ctx' = updateRecordLayer rl ctx
          { ctxHandshakeSync = HandshakeSync sync (\_ -> return ())
          }
        rl = newRecordLayer ctx callbacks
        failed = sync . ClientHandshakeFailedI
    tid <- forkIO $ E.handle failed $ do
        handshake ctx'
        void $ recvData ctx'
    wtid <- mkWeakThreadId tid
    return (quicClient wtid ask)

  where
    processI _ (SendClientHelloI mEarlySecInfo) =
        quicInstallKeys callbacks (InstallEarlyKeys mEarlySecInfo)
    processI _ (RecvServerHelloI handSecInfo) =
        quicInstallKeys callbacks (InstallHandshakeKeys handSecInfo)
    processI put (SendClientFinishedI exts appSecInfo) = do
        quicInstallKeys callbacks (InstallApplicationKeys appSecInfo)
        quicNotifyExtensions callbacks (filterQTP exts)
        put SendClientFinished
    processI put RecvSessionTicketI = put RecvSessionTicket
    processI put (ClientHandshakeFailedI e) = put (ClientHandshakeFailed e)

newQUICServer :: ServerParams -> QUICCallbacks -> IO ServerController
newQUICServer sparams callbacks = do
    (sync, ask) <- prepare processI
    ctx <- contextNew nullBackend sparams
    let ctx' = updateRecordLayer rl ctx
          { ctxHandshakeSync = HandshakeSync (\_ -> return ()) sync
          }
        rl = newRecordLayer ctx callbacks
        failed = sync . ServerHandshakeFailedI
    tid <- forkIO $ E.handle failed $ do
        handshake ctx'
        void $ recvData ctx'
    wtid <- mkWeakThreadId tid
    return (quicServer wtid ask)

  where
    processI _ (SendServerHelloI exts mEarlySecInfo handSecInfo) = do
        quicInstallKeys callbacks (InstallEarlyKeys mEarlySecInfo)
        quicInstallKeys callbacks (InstallHandshakeKeys handSecInfo)
        quicNotifyExtensions callbacks (filterQTP exts)
    processI put (SendServerFinishedI appSecInfo) = do
        quicInstallKeys callbacks (InstallApplicationKeys appSecInfo)
        put SendServerFinished
    processI put SendSessionTicketI = put SendSessionTicket
    processI put (ServerHandshakeFailedI e) = put (ServerHandshakeFailed e)

filterQTP :: [ExtensionRaw] -> [ExtensionRaw]
filterQTP = filter (\(ExtensionRaw eid _) -> eid == extensionID_QuicTransportParameters)

errorToAlertDescription :: TLSError -> AlertDescription
errorToAlertDescription = snd . head . errorToAlert

fromAlertDescription :: AlertDescription -> Word8
fromAlertDescription = valOfType

toAlertDescription :: Word8 -> Maybe AlertDescription
toAlertDescription = valToType
