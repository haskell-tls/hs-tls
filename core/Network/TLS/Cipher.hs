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
    ( BulkFunctions(..)
    , CipherKeyExchangeType(..)
    , Bulk(..)
    , Hash(..)
    , Cipher(..)
    , CipherID
    , Key
    , IV
    , cipherKeyBlockSize
    , cipherAllowedForVersion
    , cipherExchangeNeedMoreData
    ) where

import Network.TLS.Types (CipherID)
import Network.TLS.Struct (Version(..))

import qualified Data.ByteString as B

-- FIXME convert to newtype
type Key = B.ByteString
type IV = B.ByteString

data BulkFunctions =
      BulkBlockF (Key -> IV -> B.ByteString -> B.ByteString)
                 (Key -> IV -> B.ByteString -> B.ByteString)
    | BulkStreamF (Key -> IV)
                  (IV -> B.ByteString -> (B.ByteString, IV))
                  (IV -> B.ByteString -> (B.ByteString, IV))

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
    deriving (Show,Eq)

data Bulk = Bulk
    { bulkName         :: String
    , bulkKeySize      :: Int
    , bulkIVSize       :: Int
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

data Hash = Hash
    { hashName         :: String
    , hashSize         :: Int
    , hashF            :: B.ByteString -> B.ByteString
    }

instance Show Hash where
    show hash = hashName hash
instance Eq Hash where
    h1 == h2 = hashName h1 == hashName h2 && hashSize h1 == hashSize h2

-- | Cipher algorithm
data Cipher = Cipher
    { cipherID           :: CipherID
    , cipherName         :: String
    , cipherHash         :: Hash
    , cipherBulk         :: Bulk
    , cipherKeyExchange  :: CipherKeyExchangeType
    , cipherMinVer       :: Maybe Version
    }

cipherKeyBlockSize :: Cipher -> Int
cipherKeyBlockSize cipher = 2 * (hashSize (cipherHash cipher) + bulkIVSize bulk + bulkKeySize bulk)
  where bulk = cipherBulk cipher

-- | Check if a specific 'Cipher' is allowed to be used
-- with the version specified
cipherAllowedForVersion :: Version -> Cipher -> Bool
cipherAllowedForVersion ver cipher =
    case cipherMinVer cipher of
        Nothing   -> True
        Just cVer -> cVer <= ver

instance Show Cipher where
    show c = cipherName c

instance Eq Cipher where
    (==) c1 c2 = cipherID c1 == cipherID c2

cipherExchangeNeedMoreData :: CipherKeyExchangeType -> Bool
cipherExchangeNeedMoreData CipherKeyExchange_RSA         = False
cipherExchangeNeedMoreData CipherKeyExchange_DH_Anon     = True
cipherExchangeNeedMoreData CipherKeyExchange_DHE_RSA     = True
cipherExchangeNeedMoreData CipherKeyExchange_ECDHE_RSA   = True
cipherExchangeNeedMoreData CipherKeyExchange_DHE_DSS     = True
cipherExchangeNeedMoreData CipherKeyExchange_DH_DSS      = False
cipherExchangeNeedMoreData CipherKeyExchange_DH_RSA      = False
cipherExchangeNeedMoreData CipherKeyExchange_ECDH_ECDSA  = True
cipherExchangeNeedMoreData CipherKeyExchange_ECDH_RSA    = True
cipherExchangeNeedMoreData CipherKeyExchange_ECDHE_ECDSA = True
