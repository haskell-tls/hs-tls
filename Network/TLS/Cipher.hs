{-# OPTIONS_HADDOCK hide #-}
-- |
-- Module      : Network.TLS.Cipher
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Cipher
	( CipherTypeFunctions(..)
	, CipherKeyExchangeType(..)
	, Cipher(..)
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

data CipherTypeFunctions =
	  CipherNoneF -- special value for 0
	| CipherBlockF (Key -> IV -> B.ByteString -> B.ByteString)
	               (Key -> IV -> B.ByteString -> B.ByteString)
	| CipherStreamF (Key -> IV)
	                (IV -> B.ByteString -> (B.ByteString, IV))
	                (IV -> B.ByteString -> (B.ByteString, IV))

data CipherKeyExchangeType =
	  CipherKeyExchangeRSA
	| CipherKeyExchangeDHE_RSA
	| CipherKeyExchangeECDHE_RSA
	| CipherKeyExchangeDHE_DSS
	| CipherKeyExchangeDH_DSS
	| CipherKeyExchangeDH_RSA
	| CipherKeyExchangeECDH_ECDSA
	| CipherKeyExchangeECDH_RSA
	| CipherKeyExchangeECDHE_ECDSA

-- | Cipher algorithm
data Cipher = Cipher
	{ cipherID           :: Word16
	, cipherName         :: String
	, cipherDigestSize   :: Word8
	, cipherKeySize      :: Word8
	, cipherIVSize       :: Word8
	, cipherKeyBlockSize :: Word8
	, cipherPaddingSize  :: Word8
	, cipherKeyExchange  :: CipherKeyExchangeType
	, cipherMACHash      :: B.ByteString -> B.ByteString
	, cipherF            :: CipherTypeFunctions
	, cipherMinVer       :: Maybe Version
	}

instance Show Cipher where
	show c = cipherName c

instance Eq Cipher where
	(==) c1 c2 = cipherID c1 == cipherID c2

cipherExchangeNeedMoreData :: CipherKeyExchangeType -> Bool
cipherExchangeNeedMoreData CipherKeyExchangeRSA         = False
cipherExchangeNeedMoreData CipherKeyExchangeDHE_RSA     = True
cipherExchangeNeedMoreData CipherKeyExchangeECDHE_RSA   = True
cipherExchangeNeedMoreData CipherKeyExchangeDHE_DSS     = True
cipherExchangeNeedMoreData CipherKeyExchangeDH_DSS      = False
cipherExchangeNeedMoreData CipherKeyExchangeDH_RSA      = False
cipherExchangeNeedMoreData CipherKeyExchangeECDH_ECDSA  = True
cipherExchangeNeedMoreData CipherKeyExchangeECDH_RSA    = True
cipherExchangeNeedMoreData CipherKeyExchangeECDHE_ECDSA = True
