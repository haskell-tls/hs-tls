module Network.TLS.QUIC (
    -- * Hash
      hkdfExpandLabel
    , hkdfExtract
    , hashDigestSize
    -- * Extensions
    , ExtensionRaw(..)
    , ExtensionID
    ) where

import Network.TLS.Crypto (hashDigestSize)
import Network.TLS.KeySchedule (hkdfExtract, hkdfExpandLabel)
import Network.TLS.Struct (ExtensionRaw(..), ExtensionID)
