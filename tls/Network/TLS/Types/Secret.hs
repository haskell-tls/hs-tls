module Network.TLS.Types.Secret where

import Data.ByteArray (convert)
import Network.TLS.Imports
import Network.TLS.Types.Cipher

-- | Phantom type indicating early traffic secret.
data EarlySecret

-- | Phantom type indicating handshake traffic secrets.
data HandshakeSecret

-- | Phantom type indicating application traffic secrets.
data ApplicationSecret

data ResumptionSecret

newtype BaseSecret a = BaseSecret Secret

instance Show (BaseSecret a) where
    show (BaseSecret bs) = showBytesHex $ convert bs

newtype AnyTrafficSecret a = AnyTrafficSecret Secret

instance Show (AnyTrafficSecret a) where
    show (AnyTrafficSecret bs) = showBytesHex $ convert bs

-- | A client traffic secret, typed with a parameter indicating a step in the
-- TLS key schedule.
newtype ClientTrafficSecret a = ClientTrafficSecret Secret

instance Show (ClientTrafficSecret a) where
    show (ClientTrafficSecret bs) = showBytesHex $ convert bs

-- | A server traffic secret, typed with a parameter indicating a step in the
-- TLS key schedule.
newtype ServerTrafficSecret a = ServerTrafficSecret Secret

instance Show (ServerTrafficSecret a) where
    show (ServerTrafficSecret bs) = showBytesHex $ convert bs

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
    deriving (Show)

-- | Hold both client and server traffic secrets at the same step.
type TrafficSecrets a = (ClientTrafficSecret a, ServerTrafficSecret a)

-- Main secret for TLS 1.2 or earlier.
newtype MainSecret = MainSecret Secret

instance Show MainSecret where
    show (MainSecret bs) = showBytesHex $ convert bs
