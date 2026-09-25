module Network.TLS.Types (
    module Network.TLS.Types.Cipher,
    module Network.TLS.Types.Secret,
    module Network.TLS.Types.Session,
    module Network.TLS.Types.Version,
    HostName,
    Role (..),
    invertRole,
    Direction (..),
    BigNum (..),
    bigNumToInteger,
    bigNumFromInteger,
    defaultRecordSizeLimit,
    maxHandshakeSize,
    TranscriptHash (..),
    WireBytes,
) where

import Network.Socket (HostName)

import Network.TLS.Imports
import Network.TLS.Types.Cipher
import Network.TLS.Types.Secret
import Network.TLS.Types.Session
import Network.TLS.Types.Version
import Network.TLS.Util.Serialization

----------------------------------------------------------------

-- | Role
data Role = ClientRole | ServerRole
    deriving (Show, Eq)

invertRole :: Role -> Role
invertRole ClientRole = ServerRole
invertRole ServerRole = ClientRole

----------------------------------------------------------------

-- | Direction
data Direction = Tx | Rx
    deriving (Show, Eq)

----------------------------------------------------------------

newtype BigNum = BigNum ByteString
    deriving (Show, Eq)

bigNumToInteger :: BigNum -> Integer
bigNumToInteger (BigNum b) = os2ip b

bigNumFromInteger :: Integer -> BigNum
bigNumFromInteger i = BigNum $ i2osp i

----------------------------------------------------------------

-- For plaintext
-- 2^14 for TLS 1.2
-- 2^14 + 1 for TLS 1.3
defaultRecordSizeLimit :: Int
defaultRecordSizeLimit = 16384

----------------------------------------------------------------

-- | The largest handshake message we will reassemble.
--
-- A handshake message carries a 24-bit length, so a peer may announce close
-- to 16MB and then feed it a record at a time.  Records are bounded, but the
-- message they are reassembled into was not, and the fragments are held until
-- it is complete -- before anything has authenticated the peer.
--
-- The largest legitimate one is a Certificate message.  A long chain of
-- post-quantum certificates runs to tens of kilobytes, so this leaves an
-- order of magnitude over anything real while taking two orders of magnitude
-- off what a peer can ask us to hold.
maxHandshakeSize :: Int
maxHandshakeSize = 262144

----------------------------------------------------------------

newtype TranscriptHash = TranscriptHash ByteString

instance Show TranscriptHash where
    show (TranscriptHash bs) = showBytesHex bs

----------------------------------------------------------------

type WireBytes = [ByteString]
