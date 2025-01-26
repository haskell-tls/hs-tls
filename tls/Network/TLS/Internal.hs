{-# OPTIONS_HADDOCK hide #-}

module Network.TLS.Internal (
    module Network.TLS.Extension,
    module Network.TLS.IO.Decode,
    module Network.TLS.IO.Encode,
    module Network.TLS.Packet,
    module Network.TLS.Packet13,
    module Network.TLS.Struct,
    module Network.TLS.Struct13,
    module Network.TLS.Types,
    module Network.TLS.Wire,
    module Network.TLS.X509,
    sendPacket12,
    recvPacket12,
    makeCipherShowPretty,
) where

import Data.IORef

import Network.TLS.Core (recvPacket12, sendPacket12)
import Network.TLS.Extension
import Network.TLS.Extra.Cipher
import Network.TLS.IO.Decode
import Network.TLS.IO.Encode
import Network.TLS.Packet
import Network.TLS.Packet13
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types
import Network.TLS.Wire
import Network.TLS.X509 hiding (Certificate)

----------------------------------------------------------------

makeCipherShowPretty :: IO ()
makeCipherShowPretty = writeIORef globalCipherDict ciphersuite_all
