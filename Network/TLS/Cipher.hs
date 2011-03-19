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

{-
TLS 1.0 ciphers definition

CipherSuite TLS_NULL_WITH_NULL_NULL               = { 0x00,0x00 };
CipherSuite TLS_RSA_WITH_NULL_MD5                 = { 0x00,0x01 };
CipherSuite TLS_RSA_WITH_NULL_SHA                 = { 0x00,0x02 };
CipherSuite TLS_RSA_EXPORT_WITH_RC4_40_MD5        = { 0x00,0x03 };
CipherSuite TLS_RSA_WITH_RC4_128_MD5              = { 0x00,0x04 };
CipherSuite TLS_RSA_WITH_RC4_128_SHA              = { 0x00,0x05 };
CipherSuite TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5    = { 0x00,0x06 };
CipherSuite TLS_RSA_WITH_IDEA_CBC_SHA             = { 0x00,0x07 };
CipherSuite TLS_RSA_EXPORT_WITH_DES40_CBC_SHA     = { 0x00,0x08 };
CipherSuite TLS_RSA_WITH_DES_CBC_SHA              = { 0x00,0x09 };
CipherSuite TLS_RSA_WITH_3DES_EDE_CBC_SHA         = { 0x00,0x0A };
CipherSuite TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA  = { 0x00,0x0B };
CipherSuite TLS_DH_DSS_WITH_DES_CBC_SHA           = { 0x00,0x0C };
CipherSuite TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA      = { 0x00,0x0D };
CipherSuite TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA  = { 0x00,0x0E };
CipherSuite TLS_DH_RSA_WITH_DES_CBC_SHA           = { 0x00,0x0F };
CipherSuite TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA      = { 0x00,0x10 };
CipherSuite TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = { 0x00,0x11 };
CipherSuite TLS_DHE_DSS_WITH_DES_CBC_SHA          = { 0x00,0x12 };
CipherSuite TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA     = { 0x00,0x13 };
CipherSuite TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = { 0x00,0x14 };
CipherSuite TLS_DHE_RSA_WITH_DES_CBC_SHA          = { 0x00,0x15 };
CipherSuite TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA     = { 0x00,0x16 };
CipherSuite TLS_DH_anon_EXPORT_WITH_RC4_40_MD5    = { 0x00,0x17 };
CipherSuite TLS_DH_anon_WITH_RC4_128_MD5          = { 0x00,0x18 };
CipherSuite TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = { 0x00,0x19 };
CipherSuite TLS_DH_anon_WITH_DES_CBC_SHA          = { 0x00,0x1A };
CipherSuite TLS_DH_anon_WITH_3DES_EDE_CBC_SHA     = { 0x00,0x1B };
-}
