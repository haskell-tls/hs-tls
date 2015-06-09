module Network.TLS.Util.Serialization
    ( os2ip
    , i2osp
    , i2ospOf_
    , lengthBytes
    ) where

import Crypto.Number.Basic      (numBytes)
import Crypto.Number.Serialize (os2ip, i2osp, i2ospOf_)

lengthBytes :: Integer -> Int
lengthBytes = numBytes
