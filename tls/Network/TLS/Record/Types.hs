{-# LANGUAGE EmptyDataDecls #-}

-- | The Record Protocol takes messages to be transmitted, fragments
-- the data into manageable blocks.  applies a MAC, encrypts, and
-- transmits the result.  Received data is decrypted, verified,
-- reassembled, and then delivered to higher-level clients.
module Network.TLS.Record.Types (
    Header (..),
    ProtocolType (..),
    packetType,

    -- * TLS Records
    Record (..),

    -- * TLS Record fragment and constructors
    Fragment,
    fragmentGetBytes,
    fragmentPlaintext,
    fragmentCiphertext,
    Plaintext,
    Ciphertext,

    -- * manipulate record
    onRecordFragment,
    fragmentCipher,
    fragmentUncipher,

    -- * serialize record
    rawToRecord,
    recordToRaw,
    recordToHeader,
) where

import qualified Data.ByteString as B

import Network.TLS.Imports
import Network.TLS.Record.State
import Network.TLS.Struct

-- | Represent a TLS record.
data Record a = Record ProtocolType Version (Fragment a) deriving (Show, Eq)

newtype Fragment a = Fragment {fragmentGetBytes :: ByteString}
    deriving (Show, Eq)

data Plaintext
data Ciphertext

fragmentPlaintext :: ByteString -> Fragment Plaintext
fragmentPlaintext bytes = Fragment bytes

fragmentCiphertext :: ByteString -> Fragment Ciphertext
fragmentCiphertext bytes = Fragment bytes

onRecordFragment
    :: Record a -> (Fragment a -> RecordM (Fragment b)) -> RecordM (Record b)
onRecordFragment (Record pt ver frag) f = Record pt ver <$> f frag

fragmentMap
    :: (ByteString -> RecordM ByteString) -> Fragment a -> RecordM (Fragment b)
fragmentMap f (Fragment b) = Fragment <$> f b

-- | turn a compressed record into a ciphertext record using the cipher function supplied
fragmentCipher
    :: (ByteString -> RecordM ByteString)
    -> Fragment Plaintext
    -> RecordM (Fragment Ciphertext)
fragmentCipher f = fragmentMap f

-- | turn a ciphertext fragment into a plaintext fragment using the cipher function supplied
fragmentUncipher
    :: (ByteString -> RecordM ByteString)
    -> Fragment Ciphertext
    -> RecordM (Fragment Plaintext)
fragmentUncipher f = fragmentMap f

-- | turn a record into an header and bytes
recordToRaw :: Record a -> (Header, ByteString)
recordToRaw (Record pt ver (Fragment bytes)) = (Header pt ver (fromIntegral $ B.length bytes), bytes)

-- | turn a header and a fragment into a record
rawToRecord :: Header -> Fragment a -> Record a
rawToRecord (Header pt ver _) fragment = Record pt ver fragment

-- | turn a record into a header
recordToHeader :: Record a -> Header
recordToHeader (Record pt ver (Fragment bytes)) = Header pt ver (fromIntegral $ B.length bytes)
