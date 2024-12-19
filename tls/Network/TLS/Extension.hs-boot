module Network.TLS.Extension where

import Data.ByteString
import Data.Word

data ExtensionRaw = ExtensionRaw ExtensionID ByteString
instance Eq ExtensionRaw
instance Show ExtensionRaw

newtype ExtensionID = ExtensionID {fromExtensionID :: Word16}
