{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Network.TLS.QUIC
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Experimental API to run the TLS handshake establishing a QUIC connection.
--
-- On the northbound API:
--
-- * QUIC starts a TLS client or server thread with 'tlsQUICClient' or
--   'tlsQUICServer'.
--
--  TLS invokes QUIC callbacks to use the QUIC transport
--
-- * TLS uses 'quicSend' and 'quicRecv' to send and receive handshake message
--   fragments.
--
-- * TLS calls 'quicInstallKeys' to provide to QUIC the traffic secrets it
--   should use for encryption/decryption.
--
-- * TLS calls 'quicNotifyExtensions' to notify to QUIC the transport parameters
--   exchanged through the handshake protocol.
--
-- * TLS calls 'quicDone' when the handshake is done.
module Network.TLS.QUIC (
    -- * Handshakers
    tlsQUICClient,
    tlsQUICServer,

    -- * Callback
    QUICCallbacks (..),
    CryptLevel (..),
    KeyScheduleEvent (..),

    -- * Secrets
    EarlySecretInfo (..),
    HandshakeSecretInfo (..),
    ApplicationSecretInfo (..),
    EarlySecret,
    HandshakeSecret,
    ApplicationSecret,
    TrafficSecrets,
    ServerTrafficSecret (..),
    ClientTrafficSecret (..),

    -- * Negotiated parameters
    NegotiatedProtocol,
    HandshakeMode13 (..),

    -- * Extensions
    ExtensionRaw (..),
    ExtensionID (ExtensionID, EID_QuicTransportParameters),

    -- * Errors
    errorTLS,
    errorToAlertDescription,
    errorToAlertMessage,
    fromAlertDescription,
    toAlertDescription,

    -- * Hash
    hkdfExpandLabel,
    hkdfExtract,
    hashDigestSize,

    -- * Constants
    quicMaxEarlyDataSize,

    -- * Supported
    defaultSupported,
) where

import Network.TLS.Backend
import Network.TLS.Context
import Network.TLS.Context.Internal
import Network.TLS.Core
import Network.TLS.Crypto (hashDigestSize)
import Network.TLS.Crypto.Types
import Network.TLS.Extra.Cipher
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Control
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.Imports
import Network.TLS.KeySchedule (hkdfExpandLabel, hkdfExtract)
import Network.TLS.Parameters
import Network.TLS.Record.Layer
import Network.TLS.Record.State
import Network.TLS.Struct
import Network.TLS.Types

import Data.Default.Class

nullBackend :: Backend
nullBackend =
    Backend
        { backendFlush = return ()
        , backendClose = return ()
        , backendSend = \_ -> return ()
        , backendRecv = \_ -> return ""
        }

-- | Argument given to 'quicInstallKeys' when encryption material is available.
data KeyScheduleEvent
    = -- | Key material and parameters for traffic at 0-RTT level
      InstallEarlyKeys (Maybe EarlySecretInfo)
    | -- | Key material and parameters for traffic at handshake level
      InstallHandshakeKeys HandshakeSecretInfo
    | -- | Key material and parameters for traffic at application level
      InstallApplicationKeys ApplicationSecretInfo

-- | Callbacks implemented by QUIC and to be called by TLS at specific points
-- during the handshake.  TLS may invoke them from external threads but calls
-- are not concurrent.  Only a single callback function is called at a given
-- point in time.
data QUICCallbacks = QUICCallbacks
    { quicSend :: [(CryptLevel, ByteString)] -> IO ()
    -- ^ Called by TLS so that QUIC sends one or more handshake fragments. The
    -- content transiting on this API is the plaintext of the fragments and
    -- QUIC responsability is to encrypt this payload with the key material
    -- given for the specified level and an appropriate encryption scheme.
    --
    -- The size of the fragments may exceed QUIC datagram limits so QUIC may
    -- break them into smaller fragments.
    --
    -- The handshake protocol sometimes combines content at two levels in a
    -- single flight.  The TLS library does its best to provide this in the
    -- same @quicSend@ call and with a multi-valued argument.  QUIC can then
    -- decide how to transmit this optimally.
    , quicRecv :: CryptLevel -> IO (Either TLSError ByteString)
    -- ^ Called by TLS to receive from QUIC the next plaintext handshake
    -- fragment.  The argument specifies with which encryption level the
    -- fragment should be decrypted.
    --
    -- QUIC may return partial fragments to TLS.  TLS will then call
    -- @quicRecv@ again as long as necessary.  Note however that fragments
    -- must be returned in the correct sequence, i.e. the order the TLS peer
    -- emitted them.
    --
    -- The function may return an error to TLS if end of stream is reached or
    -- if a protocol error has been received, believing the handshake cannot
    -- proceed any longer.  If the TLS handshake protocol cannot recover from
    -- this error, the failure condition will be reported back to QUIC through
    -- the control interface.
    , quicInstallKeys :: Context -> KeyScheduleEvent -> IO ()
    -- ^ Called by TLS when new encryption material is ready to be used in the
    -- handshake.  The next 'quicSend' or 'quicRecv' may now use the
    -- associated encryption level (although the previous level is also
    -- possible: directions Send/Recv do not change at the same time).
    , quicNotifyExtensions :: Context -> [ExtensionRaw] -> IO ()
    -- ^ Called by TLS when QUIC-specific extensions have been received from
    -- the peer.
    , quicDone :: Context -> IO ()
    -- ^ Called when 'handshake' is done. 'tlsQUICServer' is
    -- finished after calling this hook. 'tlsQUICClient' calls
    -- 'recvData' after calling this hook to wait for new session
    -- tickets.
    }

getTxLevel :: Context -> IO CryptLevel
getTxLevel ctx = do
    (_, _, level, _) <- getTxState ctx
    return level

getRxLevel :: Context -> IO CryptLevel
getRxLevel ctx = do
    (_, _, level, _) <- getRxState ctx
    return level

newRecordLayer
    :: Context
    -> QUICCallbacks
    -> RecordLayer [(CryptLevel, ByteString)]
newRecordLayer ctx callbacks = newTransparentRecordLayer get send recv
  where
    get = getTxLevel ctx
    send = quicSend callbacks
    recv = getRxLevel ctx >>= quicRecv callbacks

-- | Start a TLS handshake thread for a QUIC client.  The client will use the
-- specified TLS parameters and call the provided callback functions to send and
-- receive handshake data.
tlsQUICClient :: ClientParams -> QUICCallbacks -> IO ()
tlsQUICClient cparams callbacks = do
    ctx0 <- contextNew nullBackend cparams
    let ctx1 =
            ctx0
                { ctxHandshakeSync = HandshakeSync sync (\_ _ -> return ())
                , ctxFragmentSize = Nothing
                , ctxQUICMode = True
                }
        rl = newRecordLayer ctx2 callbacks
        ctx2 = updateRecordLayer rl ctx1
    handshake ctx2
    quicDone callbacks ctx2
    void $ recvData ctx2 -- waiting for new session tickets
  where
    sync ctx (SendClientHello mEarlySecInfo) =
        quicInstallKeys callbacks ctx (InstallEarlyKeys mEarlySecInfo)
    sync ctx (RecvServerHello handSecInfo) =
        quicInstallKeys callbacks ctx (InstallHandshakeKeys handSecInfo)
    sync ctx (SendClientFinished exts appSecInfo) = do
        let qexts = filterQTP exts
        when (null qexts) $ do
            throwCore $
                Error_Protocol "QUIC transport parameters are mssing" MissingExtension
        quicNotifyExtensions callbacks ctx qexts
        quicInstallKeys callbacks ctx (InstallApplicationKeys appSecInfo)

-- | Start a TLS handshake thread for a QUIC server.  The server will use the
-- specified TLS parameters and call the provided callback functions to send and
-- receive handshake data.
tlsQUICServer :: ServerParams -> QUICCallbacks -> IO ()
tlsQUICServer sparams callbacks = do
    ctx0 <- contextNew nullBackend sparams
    let ctx1 =
            ctx0
                { ctxHandshakeSync = HandshakeSync (\_ _ -> return ()) sync
                , ctxFragmentSize = Nothing
                , ctxQUICMode = True
                }
        rl = newRecordLayer ctx2 callbacks
        ctx2 = updateRecordLayer rl ctx1
    handshake ctx2
    quicDone callbacks ctx2
  where
    sync ctx (SendServerHello exts mEarlySecInfo handSecInfo) = do
        let qexts = filterQTP exts
        when (null qexts) $ do
            throwCore $
                Error_Protocol "QUIC transport parameters are mssing" MissingExtension
        quicNotifyExtensions callbacks ctx qexts
        quicInstallKeys callbacks ctx (InstallEarlyKeys mEarlySecInfo)
        quicInstallKeys callbacks ctx (InstallHandshakeKeys handSecInfo)
    sync ctx (SendServerFinished appSecInfo) =
        quicInstallKeys callbacks ctx (InstallApplicationKeys appSecInfo)

filterQTP :: [ExtensionRaw] -> [ExtensionRaw]
filterQTP =
    filter
        (\(ExtensionRaw eid _) -> eid == EID_QuicTransportParameters)

-- | Can be used by callbacks to signal an unexpected condition.  This will then
-- generate an "internal_error" alert in the TLS stack.
errorTLS :: String -> IO a
errorTLS msg = throwCore $ Error_Protocol msg InternalError

-- | Return the alert that a TLS endpoint would send to the peer for the
-- specified library error.
errorToAlertDescription :: TLSError -> AlertDescription
errorToAlertDescription = snd . errorToAlert

-- | Decode an alert from the assigned value.
toAlertDescription :: Word8 -> AlertDescription
toAlertDescription = AlertDescription

defaultSupported :: Supported
defaultSupported =
    def
        { supportedVersions = [TLS13]
        , supportedCiphers =
            [ cipher_TLS13_AES256GCM_SHA384
            , cipher_TLS13_AES128GCM_SHA256
            , cipher_TLS13_AES128CCM_SHA256
            ]
        , supportedGroups = [X25519, X448, P256, P384, P521]
        }

-- | Max early data size for QUIC.
quicMaxEarlyDataSize :: Int
quicMaxEarlyDataSize = 0xffffffff
