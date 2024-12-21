{-# OPTIONS_HADDOCK hide #-}

module Network.TLS.Internal (
    module Network.TLS.Extension,
    module Network.TLS.Packet,
    module Network.TLS.Packet13,
    module Network.TLS.Receiving,
    module Network.TLS.Sending,
    module Network.TLS.Struct,
    module Network.TLS.Struct13,
    module Network.TLS.Types,
    module Network.TLS.Wire,
    sendPacket12,
    recvPacket12,
    makeCipherShowPretty,
) where

import Data.IORef

import Network.TLS.Core (recvPacket12, sendPacket12)
import Network.TLS.Extension
import Network.TLS.Extra.Cipher
import Network.TLS.Packet
import Network.TLS.Packet13
import Network.TLS.Receiving
import Network.TLS.Sending
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types
import Network.TLS.Wire

----------------------------------------------------------------

makeCipherShowPretty :: IO ()
makeCipherShowPretty = writeIORef globalCipherDict ciphersuite_all
