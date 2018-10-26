module Network.TLS.Handshake.Random (
      serverRandom
    , clientRandom
    ) where

import Network.TLS.Context.Internal
import Network.TLS.Struct

serverRandom :: Context -> IO ServerRandom
serverRandom ctx = ServerRandom <$> getStateRNG ctx 32

-- ClientRandom in the second client hello for retry must be
-- the same as the first one.
clientRandom :: Context -> Maybe ClientRandom -> IO ClientRandom
clientRandom ctx Nothing   = ClientRandom <$> getStateRNG ctx 32
clientRandom _   (Just cr) = return cr
