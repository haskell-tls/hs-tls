-- |
-- Module      : Network.TLS.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Types
    ( Version(..)
    , SessionID
    , SessionData(..)
    , CipherID
    , CompressionID
    , Role(..)
    , invertRole
    , Direction(..)
    ) where

import Network.TLS.Imports

type HostName = String

-- | Versions known to TLS
--
-- SSL2 is just defined, but this version is and will not be supported.
data Version = SSL2 | SSL3 | TLS10 | TLS11 | TLS12 deriving (Show, Eq, Ord, Bounded)

-- | A session ID
type SessionID = ByteString

-- | Session data to resume
data SessionData = SessionData
    { sessionVersion     :: Version
    , sessionCipher      :: CipherID
    , sessionCompression :: CompressionID
    , sessionClientSNI   :: Maybe HostName
    , sessionSecret      :: ByteString
    } deriving (Show,Eq)

-- | Cipher identification
type CipherID = Word16

-- | Compression identification
type CompressionID = Word8

-- | Role
data Role = ClientRole | ServerRole
    deriving (Show,Eq)

-- | Direction
data Direction = Tx | Rx
    deriving (Show,Eq)

invertRole :: Role -> Role
invertRole ClientRole = ServerRole
invertRole ServerRole = ClientRole
