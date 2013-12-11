-- |
-- Module      : Network.TLS.Context
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Hooks
    ( Logging(..)
    , defaultLogging
    , Hooks(..)
    , defaultHooks
    ) where

import qualified Data.ByteString as B
import Network.TLS.Struct (Header, Handshake(..))

-- | Hooks for logging 
data Logging = Logging
    { loggingPacketSent :: String -> IO ()
    , loggingPacketRecv :: String -> IO ()
    , loggingIOSent     :: B.ByteString -> IO ()
    , loggingIORecv     :: Header -> B.ByteString -> IO ()
    }

defaultLogging :: Logging
defaultLogging = Logging
    { loggingPacketSent = (\_ -> return ())
    , loggingPacketRecv = (\_ -> return ())
    , loggingIOSent     = (\_ -> return ())
    , loggingIORecv     = (\_ _ -> return ())
    }

-- | A collection of hooks actions.
data Hooks = Hooks
    { hookRecvHandshake :: Handshake -> IO Handshake
    }

defaultHooks :: Hooks
defaultHooks = Hooks
    { hookRecvHandshake = \hs -> return hs
    }

