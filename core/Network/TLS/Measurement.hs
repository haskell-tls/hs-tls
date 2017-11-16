-- |
-- Module      : Network.TLS.Measurement
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Measurement
        ( Measurement(..)
        , newMeasurement
        , addBytesReceived
        , addBytesSent
        , resetBytesCounters
        , incrementNbHandshakes
        ) where

import Network.TLS.Imports

-- | record some data about this connection.
data Measurement = Measurement
        { nbHandshakes  :: !Word32 -- ^ number of handshakes on this context
        , bytesReceived :: !Word32 -- ^ bytes received since last handshake
        , bytesSent     :: !Word32 -- ^ bytes sent since last handshake
        } deriving (Show,Eq)

newMeasurement :: Measurement
newMeasurement = Measurement
        { nbHandshakes  = 0
        , bytesReceived = 0
        , bytesSent     = 0
        }

addBytesReceived :: Int -> Measurement -> Measurement
addBytesReceived sz measure =
        measure { bytesReceived = bytesReceived measure + fromIntegral sz }

addBytesSent :: Int -> Measurement -> Measurement
addBytesSent sz measure =
        measure { bytesSent = bytesSent measure + fromIntegral sz }

resetBytesCounters :: Measurement -> Measurement
resetBytesCounters measure = measure { bytesReceived = 0, bytesSent = 0 }

incrementNbHandshakes :: Measurement -> Measurement
incrementNbHandshakes measure =
        measure { nbHandshakes = nbHandshakes measure + 1 }
