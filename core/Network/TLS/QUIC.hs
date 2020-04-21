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

data QuicSecretEvent
    = SyncEarlySecret (Maybe EarlySecretInfo)
    | SyncHandshakeSecret HandshakeSecretInfo
    | SyncApplicationSecret ApplicationSecretInfo

data QuicCallbacks = QuicCallbacks
    { quicSend              :: [(CryptLevel, ByteString)] -> IO ()
    , quicRecv              :: CryptLevel -> IO ByteString
    , quicNotifySecretEvent :: QuicSecretEvent -> IO ()
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

prepare :: (IO () -> a -> IO ()) -> IO (a -> IO (), IO a)
prepare processI = do
    mvar <- newEmptyMVar
    let sync a = processI (putMVar mvar a) a
        ask  = takeMVar mvar
    return (sync, ask)

newRecordLayer :: Context -> QuicCallbacks
               -> RecordLayer [(CryptLevel, ByteString)]
newRecordLayer ctx callbacks = newTransparentRecordLayer get send recv
  where
    get     = getTxLevel ctx
    send    = quicSend callbacks
    recv    = getRxLevel ctx >>= quicRecv callbacks

newQUICClient :: ClientParams -> QuicCallbacks -> IO ClientController
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
    processI notify (SendClientHelloI mEarlySecInfo) = do
        quicNotifySecretEvent callbacks (SyncEarlySecret mEarlySecInfo)
        notify
    processI notify (RecvServerHelloI handSecInfo) = do
        quicNotifySecretEvent callbacks (SyncHandshakeSecret handSecInfo)
        notify
    processI notify (SendClientFinishedI exts appSecInfo) = do
        quicNotifySecretEvent callbacks (SyncApplicationSecret appSecInfo)
        quicNotifyExtensions callbacks (filterQTP exts)
        notify
    processI notify RecvSessionTicketI = notify
    processI notify (ClientHandshakeFailedI _) = notify

newQUICServer :: ServerParams -> QuicCallbacks -> IO ServerController
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
    processI _      (SendServerHelloI exts mEarlySecInfo handSecInfo) = do
        quicNotifySecretEvent callbacks (SyncEarlySecret mEarlySecInfo)
        quicNotifySecretEvent callbacks (SyncHandshakeSecret handSecInfo)
        quicNotifyExtensions callbacks (filterQTP exts)
    processI notify (SendServerFinishedI appSecInfo) = do
        quicNotifySecretEvent callbacks (SyncApplicationSecret appSecInfo)
        notify
    processI notify SendSessionTicketI = notify
    processI notify (ServerHandshakeFailedI _) = notify

filterQTP :: [ExtensionRaw] -> [ExtensionRaw]
filterQTP = filter (\(ExtensionRaw eid _) -> eid == extensionID_QuicTransportParameters)

errorToAlertDescription :: TLSError -> AlertDescription
errorToAlertDescription = snd . head . errorToAlert

fromAlertDescription :: AlertDescription -> Word8
fromAlertDescription = valOfType

toAlertDescription :: Word8 -> Maybe AlertDescription
toAlertDescription = valToType
