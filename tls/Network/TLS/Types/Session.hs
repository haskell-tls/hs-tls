{-# LANGUAGE DeriveGeneric #-}

module Network.TLS.Types.Session where

import Codec.Serialise
import qualified Data.ByteString as B
import GHC.Generics
import Network.Socket (HostName)

import Network.TLS.Crypto (Group, Hash (..), hash)
import Network.TLS.Imports
import Network.TLS.Types.Cipher
import Network.TLS.Types.Version

-- | A session ID
type SessionID = ByteString

-- | Identity
type SessionIDorTicket = ByteString

-- | Encrypted session ticket (encrypt(encode 'SessionData')).
type Ticket = ByteString

isTicket :: SessionIDorTicket -> Bool
isTicket x
    | B.length x > 32 = True
    | otherwise = False

toSessionID :: Ticket -> SessionID
toSessionID = hash SHA256

-- | Compression identification
type CompressionID = Word8

-- | Session data to resume
data SessionData = SessionData
    { sessionVersion :: Version
    , sessionCipher :: CipherID
    , sessionCompression :: CompressionID
    , sessionClientSNI :: Maybe HostName
    , sessionSecret :: ByteString
    , sessionGroup :: Maybe Group
    , sessionTicketInfo :: Maybe TLS13TicketInfo
    , sessionALPN :: Maybe ByteString
    , sessionMaxEarlyDataSize :: Int
    , sessionFlags :: [SessionFlag]
    } -- sessionFromTicket :: Bool
    deriving (Show, Eq, Generic)

is0RTTPossible :: SessionData -> Bool
is0RTTPossible sd = sessionMaxEarlyDataSize sd > 0

-- | Some session flags
data SessionFlag
    = -- | Session created with Extended Main Secret
      SessionEMS
    deriving (Show, Eq, Enum, Generic)

type Second = Word32
type Millisecond = Word64

data TLS13TicketInfo = TLS13TicketInfo
    { lifetime :: Second -- NewSessionTicket.ticket_lifetime in seconds
    , ageAdd :: Second -- NewSessionTicket.ticket_age_add
    , txrxTime :: Millisecond -- serverSendTime or clientReceiveTime
    , estimatedRTT :: Maybe Millisecond
    }
    deriving (Show, Eq, Generic)

instance Serialise TLS13TicketInfo
instance Serialise SessionFlag
instance Serialise SessionData
