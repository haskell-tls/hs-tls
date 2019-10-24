module Network.TLS.QUIC (
    -- * Hash
      hkdfExpandLabel
    , hkdfExtract
    , hashDigestSize
    ) where

import Network.TLS.Crypto (hashDigestSize)
import Network.TLS.KeySchedule (hkdfExtract, hkdfExpandLabel)
