module Network.TLS.Handshake.Random where

import Network.TLS.Context.Internal
import Network.TLS.Struct

serverRandom :: Context -> IO ServerRandom
serverRandom ctx = ServerRandom <$> getStateRNG ctx 32

clientRandom :: Context -> IO ClientRandom
clientRandom ctx = ClientRandom <$> getStateRNG ctx 32

