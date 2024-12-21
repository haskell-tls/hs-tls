-- This is a breaker for cyclic imports:
--
-- - Network.TLS.Extension imports Network.TLS.Struct
-- - Network.TLS.Extension imports Network.TLS.Packet
--
-- - Network.TLS.Struct imports Network.TLS.Extension
--
-- - Network.TLS.Packet imports Network.TLS.Struct
--
-- Originally, ExtensionRaw was defined in Network.TLS.Struct and no
-- cyclic imports exist. It is moved into Network.TLS.Extension for
-- pretty-printing, so the cyclic imports happen.
module Network.TLS.Extension where

import Data.ByteString
import Data.Word

data ExtensionRaw = ExtensionRaw ExtensionID ByteString
instance Eq ExtensionRaw
instance Show ExtensionRaw

newtype ExtensionID = ExtensionID {fromExtensionID :: Word16}
