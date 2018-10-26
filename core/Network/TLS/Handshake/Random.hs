module Network.TLS.Handshake.Random (
      serverRandom
    , clientRandom
    , hrrRandom
    , isHelloRetryRequest
    ) where

import qualified Data.ByteString as B
import Network.TLS.Context.Internal
import Network.TLS.Struct

serverRandom :: Context -> IO ServerRandom
serverRandom ctx = ServerRandom <$> getStateRNG ctx 32

-- ClientRandom in the second client hello for retry must be
-- the same as the first one.
clientRandom :: Context -> Maybe ClientRandom -> IO ClientRandom
clientRandom ctx Nothing   = ClientRandom <$> getStateRNG ctx 32
clientRandom _   (Just cr) = return cr

hrrRandom :: ServerRandom
hrrRandom = ServerRandom $ B.pack [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11
  , 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91
  , 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E
  , 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
  ]

isHelloRetryRequest :: ServerRandom -> Bool
isHelloRetryRequest = (== hrrRandom)
