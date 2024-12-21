module Network.TLS.Types.Secret where

import Network.TLS.Imports

-- | Phantom type indicating early traffic secret.
data EarlySecret

-- | Phantom type indicating handshake traffic secrets.
data HandshakeSecret

-- | Phantom type indicating application traffic secrets.
data ApplicationSecret

data ResumptionSecret

newtype BaseSecret a = BaseSecret ByteString deriving (Show)
newtype AnyTrafficSecret a = AnyTrafficSecret ByteString deriving (Show)

-- | A client traffic secret, typed with a parameter indicating a step in the
-- TLS key schedule.
newtype ClientTrafficSecret a = ClientTrafficSecret ByteString deriving (Show)

-- | A server traffic secret, typed with a parameter indicating a step in the
-- TLS key schedule.
newtype ServerTrafficSecret a = ServerTrafficSecret ByteString deriving (Show)

data SecretTriple a = SecretTriple
    { triBase :: BaseSecret a
    , triClient :: ClientTrafficSecret a
    , triServer :: ServerTrafficSecret a
    }
    deriving (Show)

data SecretPair a = SecretPair
    { pairBase :: BaseSecret a
    , pairClient :: ClientTrafficSecret a
    }

-- | Hold both client and server traffic secrets at the same step.
type TrafficSecrets a = (ClientTrafficSecret a, ServerTrafficSecret a)

-- Main secret for TLS 1.2 or earlier.
newtype MainSecret = MainSecret ByteString deriving (Show)
