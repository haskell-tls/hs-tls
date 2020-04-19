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
    { quicRecv              :: CryptLevel -> IO ByteString
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

prepare :: (a -> IO ())
        -> IO (IO ByteString
              ,a -> IO ()
              ,IO a
              ,ByteString -> IO ())
prepare processI = do
    c1 <- newChan
    mvar <- newEmptyMVar
    let send = writeChan c1
        get  = readChan  c1
        sync a = processI a >> putMVar mvar a
        ask  = takeMVar mvar
    return (get, sync, ask, send)

newRecordLayer :: Context -> QuicCallbacks
               -> (ByteString -> IO ())
               -> RecordLayer [(CryptLevel, ByteString)]
newRecordLayer ctx callbacks send = newTransparentRecordLayer get send recv
  where
    get     = getTxLevel ctx
    recv    = getRxLevel ctx >>= quicRecv callbacks

newQUICClient :: ClientParams -> QuicCallbacks -> IO ClientController
newQUICClient cparams callbacks = do
    (get, sync, ask, send) <- prepare processI
    ctx <- contextNew nullBackend cparams
    let ctx' = updateRecordLayer rl ctx
          { ctxHandshakeSync = HandshakeSync sync (\_ -> return ())
          }
        rl = newRecordLayer ctx callbacks send
        failed = sync . ClientHandshakeFailedI
    tid <- forkIO $ E.handle failed $ do
        handshake ctx'
        void $ recvData ctx'
    wtid <- mkWeakThreadId tid
    return (quicClient wtid ask get)

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
    (get, sync, ask, send) <- prepare processI
    ctx <- contextNew nullBackend sparams
    let ctx' = updateRecordLayer rl ctx
          { ctxHandshakeSync = HandshakeSync (\_ -> return ()) sync
          }
        rl = newRecordLayer ctx callbacks send
        failed = sync . ServerHandshakeFailedI
    tid <- forkIO $ E.handle failed $ do
        handshake ctx'
        void $ recvData ctx'
    wtid <- mkWeakThreadId tid
    return (quicServer wtid ask get)

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
