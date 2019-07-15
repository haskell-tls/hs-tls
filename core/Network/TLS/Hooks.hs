-- |
-- Module      : Network.TLS.Context
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Hooks
    ( Logging(..)
    , Hooks(..)
    , defaultHooks
    ) where

import qualified Data.ByteString as B
import Network.TLS.Struct (Header, Handshake)
import Network.TLS.Struct13 (Handshake13)
import Network.TLS.X509 (CertificateChain)
import Data.Default.Class

-- | Hooks for logging
--
-- This is called when sending and receiving packets and IO
data Logging = Logging
    { loggingPacketSent :: String -> IO ()
    , loggingPacketRecv :: String -> IO ()
    , loggingIOSent     :: B.ByteString -> IO ()
    , loggingIORecv     :: Header -> B.ByteString -> IO ()
    }

defaultLogging :: Logging
defaultLogging = Logging
    { loggingPacketSent = \_ -> return ()
    , loggingPacketRecv = \_ -> return ()
    , loggingIOSent     = \_ -> return ()
    , loggingIORecv     = \_ _ -> return ()
    }

instance Default Logging where
    def = defaultLogging

-- | A collection of hooks actions.
data Hooks = Hooks
    { -- | called at each handshake message received
      hookRecvHandshake    :: Handshake -> IO Handshake
      -- | called at each handshake message received for TLS 1.3
    , hookRecvHandshake13  :: Handshake13 -> IO Handshake13
      -- | called at each certificate chain message received
    , hookRecvCertificates :: CertificateChain -> IO ()
      -- | hooks on IO and packets, receiving and sending.
    , hookLogging          :: Logging
    }

defaultHooks :: Hooks
defaultHooks = Hooks
    { hookRecvHandshake    = return
    , hookRecvHandshake13  = return
    , hookRecvCertificates = return . const ()
    , hookLogging          = def
    }

instance Default Hooks where
    def = defaultHooks
