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
        , cipherKeyBlockSize
        , Key
        , IV
        , cipherExchangeNeedMoreData
        ) where

import Data.Word
import Network.TLS.Struct (Version(..))

import qualified Data.ByteString as B

-- FIXME convert to newtype
type Key = B.ByteString
type IV = B.ByteString

data BulkFunctions =
          BulkNoneF -- special value for 0
        | BulkBlockF (Key -> IV -> B.ByteString -> B.ByteString)
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

data Hash = Hash
        { hashName         :: String
        , hashSize         :: Int
        , hashF            :: B.ByteString -> B.ByteString
        }

-- | Cipher algorithm
data Cipher = Cipher
        { cipherID           :: Word16
        , cipherName         :: String
        , cipherHash         :: Hash
        , cipherBulk         :: Bulk
        , cipherKeyExchange  :: CipherKeyExchangeType
        , cipherMinVer       :: Maybe Version
        }

cipherKeyBlockSize :: Cipher -> Int
cipherKeyBlockSize cipher = 2 * (hashSize (cipherHash cipher) + bulkIVSize bulk + bulkKeySize bulk)
        where bulk = cipherBulk cipher

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
