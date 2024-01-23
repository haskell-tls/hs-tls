{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE PatternSynonyms #-}

-- |
-- Module      : Network.TLS.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
module Network.TLS.Types (
    Version (Version, SSL2, SSL3, TLS10, TLS11, TLS12, TLS13),
    SessionID,
    SessionIDorTicket,
    Ticket,
    isTicket,
    toSessionID,
    SessionData (..),
    SessionFlag (..),
    CertReqContext,
    TLS13TicketInfo (..),
    CipherID,
    CompressionID,
    Role (..),
    invertRole,
    Direction (..),
    HostName,
    Second,
    Millisecond,
    EarlySecret,
    HandshakeSecret,
    ApplicationSecret,
    ResumptionSecret,
    BaseSecret (..),
    AnyTrafficSecret (..),
    ClientTrafficSecret (..),
    ServerTrafficSecret (..),
    TrafficSecrets,
    SecretTriple (..),
    SecretPair (..),
    MasterSecret (..),
) where

import qualified Data.ByteString as B
import GHC.Generics
import Network.Socket (HostName)
import Network.TLS.Crypto (Group, Hash (..), hash)
import Network.TLS.Imports

type Second = Word32
type Millisecond = Word64

-- | Versions known to TLS
newtype Version = Version Word16 deriving (Eq, Ord, Generic)
{- FOURMOLU_DISABLE -}
pattern SSL2  :: Version
pattern SSL2   = Version 0x0200
pattern SSL3  :: Version
pattern SSL3   = Version 0x0300
pattern TLS10 :: Version
pattern TLS10  = Version 0x0301
pattern TLS11 :: Version
pattern TLS11  = Version 0x0302
pattern TLS12 :: Version
pattern TLS12  = Version 0x0303
pattern TLS13 :: Version
pattern TLS13  = Version 0x0304

instance Show Version where
    show SSL2  = "SSL2"
    show SSL3  = "SSL3"
    show TLS10 = "TLS1.0"
    show TLS11 = "TLS1.1"
    show TLS12 = "TLS1.2"
    show TLS13 = "TLS1.3"
    show (Version x) = "Version " ++ show x
{- FOURMOLU_ENABLE -}

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

-- | Some session flags
data SessionFlag
    = -- | Session created with Extended Master Secret
      SessionEMS
    deriving (Show, Eq, Enum, Generic)

-- | Certificate request context for TLS 1.3.
type CertReqContext = ByteString

data TLS13TicketInfo = TLS13TicketInfo
    { lifetime :: Second -- NewSessionTicket.ticket_lifetime in seconds
    , ageAdd :: Second -- NewSessionTicket.ticket_age_add
    , txrxTime :: Millisecond -- serverSendTime or clientReceiveTime
    , estimatedRTT :: Maybe Millisecond
    }
    deriving (Show, Eq, Generic)

-- | Cipher identification
type CipherID = Word16

-- | Compression identification
type CompressionID = Word8

-- | Role
data Role = ClientRole | ServerRole
    deriving (Show, Eq)

-- | Direction
data Direction = Tx | Rx
    deriving (Show, Eq)

invertRole :: Role -> Role
invertRole ClientRole = ServerRole
invertRole ServerRole = ClientRole

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

-- Master secret for TLS 1.2 or earlier.
newtype MasterSecret = MasterSecret ByteString deriving (Show)
