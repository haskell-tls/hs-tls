{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE ExistentialQuantification #-}
-- |
-- Module      : Network.TLS.Cipher
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Cipher
    ( CipherKeyExchangeType(..)
    , Bulk(..)
    , BulkFunctions(..)
    , BulkDirection(..)
    , BulkState(..)
    , BulkStream(..)
    , BulkBlock
    , BulkAEAD
    , bulkInit
    , Hash(..)
    , Cipher(..)
    , CipherID
    , cipherKeyBlockSize
    , BulkKey
    , BulkIV
    , BulkNonce
    , BulkAdditionalData
    , cipherAllowedForVersion
    , hasMAC
    , hasRecordIV
    ) where

import Crypto.Cipher.Types (AuthTag)
import Network.TLS.Types (CipherID, Version(..))
import Network.TLS.Crypto (Hash(..), hashDigestSize)

import qualified Data.ByteString as B

-- FIXME convert to newtype
type BulkKey = B.ByteString
type BulkIV = B.ByteString
type BulkNonce = B.ByteString
type BulkAdditionalData = B.ByteString

data BulkState =
      BulkStateStream BulkStream
    | BulkStateBlock  BulkBlock
    | BulkStateAEAD   BulkAEAD
    | BulkStateUninitialized

instance Show BulkState where
    show (BulkStateStream _)      = "BulkStateStream"
    show (BulkStateBlock _)       = "BulkStateBlock"
    show (BulkStateAEAD _)        = "BulkStateAEAD"
    show  BulkStateUninitialized  = "BulkStateUninitialized"

newtype BulkStream = BulkStream (B.ByteString -> (B.ByteString, BulkStream))

type BulkBlock = BulkIV -> B.ByteString -> (B.ByteString, BulkIV)

type BulkAEAD = BulkNonce -> B.ByteString -> BulkAdditionalData -> (B.ByteString, AuthTag)

data BulkDirection = BulkEncrypt | BulkDecrypt
    deriving (Show,Eq)

bulkInit :: Bulk -> BulkDirection -> BulkKey -> BulkState
bulkInit bulk direction key =
    case bulkF bulk of
        BulkBlockF  ini -> BulkStateBlock  (ini direction key)
        BulkStreamF ini -> BulkStateStream (ini direction key)
        BulkAeadF   ini -> BulkStateAEAD   (ini direction key)

data BulkFunctions =
      BulkBlockF  (BulkDirection -> BulkKey -> BulkBlock)
    | BulkStreamF (BulkDirection -> BulkKey -> BulkStream)
    | BulkAeadF   (BulkDirection -> BulkKey -> BulkAEAD)

hasMAC,hasRecordIV :: BulkFunctions -> Bool

hasMAC (BulkBlockF _ ) = True
hasMAC (BulkStreamF _) = True
hasMAC (BulkAeadF _  ) = False

hasRecordIV = hasMAC

data CipherKeyExchangeType =
      CipherKeyExchange_RSA
    | CipherKeyExchange_DH_Anon
    | CipherKeyExchange_DHE_RSA
    | CipherKeyExchange_ECDHE_RSA
    | CipherKeyExchange_DHE_DSS
    | CipherKeyExchange_DH_DSS
    | CipherKeyExchange_DH_RSA
    | CipherKeyExchange_ECDH_ECDSA
    | CipherKeyExchange_ECDH_RSA
    | CipherKeyExchange_ECDHE_ECDSA
    | CipherKeyExchange_TLS13 -- not expressed in cipher suite
    deriving (Show,Eq)

data Bulk = Bulk
    { bulkName         :: String
    , bulkKeySize      :: Int
    , bulkIVSize       :: Int
    , bulkExplicitIV   :: Int -- Explicit size for IV for AEAD Cipher, 0 otherwise
    , bulkAuthTagLen   :: Int -- Authentication tag length in bytes for AEAD Cipher, 0 otherwise
    , bulkBlockSize    :: Int
    , bulkF            :: BulkFunctions
    }

instance Show Bulk where
    show bulk = bulkName bulk
instance Eq Bulk where
    b1 == b2 = and [ bulkName b1 == bulkName b2
                   , bulkKeySize b1 == bulkKeySize b2
                   , bulkIVSize b1 == bulkIVSize b2
                   , bulkBlockSize b1 == bulkBlockSize b2
                   ]

-- | Cipher algorithm
data Cipher = Cipher
    { cipherID           :: CipherID
    , cipherName         :: String
    , cipherHash         :: Hash
    , cipherBulk         :: Bulk
    , cipherKeyExchange  :: CipherKeyExchangeType
    , cipherMinVer       :: Maybe Version
    , cipherPRFHash      :: Maybe Hash
    }

cipherKeyBlockSize :: Cipher -> Int
cipherKeyBlockSize cipher = 2 * (hashDigestSize (cipherHash cipher) + bulkIVSize bulk + bulkKeySize bulk)
  where bulk = cipherBulk cipher

-- | Check if a specific 'Cipher' is allowed to be used
-- with the version specified
cipherAllowedForVersion :: Version -> Cipher -> Bool
cipherAllowedForVersion ver cipher =
    case cipherMinVer cipher of
        Nothing   -> ver < TLS13
        Just cVer -> cVer <= ver && (ver < TLS13 || cVer >= TLS13)

instance Show Cipher where
    show c = cipherName c

instance Eq Cipher where
    (==) c1 c2 = cipherID c1 == cipherID c2
