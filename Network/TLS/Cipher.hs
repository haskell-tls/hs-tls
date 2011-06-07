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
