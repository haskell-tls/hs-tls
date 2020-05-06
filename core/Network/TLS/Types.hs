{-# LANGUAGE EmptyDataDecls #-}
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
    , SessionFlag(..)
    , CertReqContext
    , TLS13TicketInfo(..)
    , CipherID
    , CompressionID
    , Role(..)
    , invertRole
    , Direction(..)
    , HostName
    , Second
    , Millisecond
    , EarlySecret
    , HandshakeSecret
    , ApplicationSecret
    , ResumptionSecret
    , BaseSecret(..)
    , AnyTrafficSecret(..)
    , ClientTrafficSecret(..)
    , ServerTrafficSecret(..)
    , TrafficSecrets
    , SecretTriple(..)
    , SecretPair(..)
    , MasterSecret(..)
    ) where

import Network.TLS.Imports
import Network.TLS.Crypto.Types (Group)

type HostName    = String
type Second      = Word32
type Millisecond = Word64

-- | Versions known to TLS
--
-- SSL2 is just defined, but this version is and will not be supported.
data Version = SSL2 | SSL3 | TLS10 | TLS11 | TLS12 | TLS13 deriving (Show, Eq, Ord, Bounded)

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
    , sessionFlags       :: [SessionFlag]
    } deriving (Show,Eq)

-- | Some session flags
data SessionFlag
    = SessionEMS        -- ^ Session created with Extended Master Secret
    deriving (Show,Eq,Enum)

-- | Certificate request context for TLS 1.3.
type CertReqContext = ByteString

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

-- | Phantom type indicating early traffic secret.
data EarlySecret

-- | Phantom type indicating handshake traffic secrets.
data HandshakeSecret

-- | Phantom type indicating application traffic secrets.
data ApplicationSecret

data ResumptionSecret

newtype BaseSecret a = BaseSecret ByteString deriving Show
newtype AnyTrafficSecret a = AnyTrafficSecret ByteString deriving Show

-- | A client traffic secret, typed with a parameter indicating a step in the
-- TLS key schedule.
newtype ClientTrafficSecret a = ClientTrafficSecret ByteString deriving Show

-- | A server traffic secret, typed with a parameter indicating a step in the
-- TLS key schedule.
newtype ServerTrafficSecret a = ServerTrafficSecret ByteString deriving Show

data SecretTriple a = SecretTriple
    { triBase   :: BaseSecret a
    , triClient :: ClientTrafficSecret a
    , triServer :: ServerTrafficSecret a
    }

data SecretPair a = SecretPair
    { pairBase   :: BaseSecret a
    , pairClient :: ClientTrafficSecret a
    }

-- | Hold both client and server traffic secrets at the same step.
type TrafficSecrets a = (ClientTrafficSecret a, ServerTrafficSecret a)

-- Master secret for TLS 1.2 or earlier.
newtype MasterSecret = MasterSecret ByteString deriving Show
