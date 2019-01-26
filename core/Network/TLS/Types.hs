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
    , TLS13TicketInfo(..)
    , CipherID
    , CompressionID
    , Role(..)
    , invertRole
    , Direction(..)
    , HostName
    , Second
    , Millisecond
    ) where

import Network.TLS.Imports
import Network.TLS.Crypto.Types (Group)

type HostName    = String
type Second      = Word32
type Millisecond = Word64

-- | Versions known to TLS
--
-- SSL2 is just defined, but this version is and will not be supported.
data Version = SSL2 | SSL3 | TLS10 | DTLS10 | TLS11 | TLS12 | DTLS12 | TLS13 deriving (Show, Eq, Ord, Bounded)

-- | A session ID
type SessionID = ByteString

-- | Session data to resume
data SessionData = SessionData
    { sessionVersion     :: Version
    , sessionCipher      :: CipherID
    , sessionCompression :: CompressionID
    , sessionClientSNI   :: Maybe HostName
    , sessionSecret      :: ByteString
    , sessionGroup       :: Maybe Group
    , sessionTicketInfo  :: Maybe TLS13TicketInfo
    , sessionALPN        :: Maybe ByteString
    , sessionMaxEarlyDataSize :: Int
    } deriving (Show,Eq)

data TLS13TicketInfo = TLS13TicketInfo
    { lifetime :: Second      -- NewSessionTicket.ticket_lifetime in seconds
    , ageAdd   :: Second      -- NewSessionTicket.ticket_age_add
    , txrxTime :: Millisecond -- serverSendTime or clientReceiveTime
    , estimatedRTT :: Maybe Millisecond
    } deriving (Show, Eq)

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
