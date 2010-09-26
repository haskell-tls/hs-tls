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
	, cipherExchangeNeedMoreData

	-- * builtin ciphers for ease of use, might move later to a tls-ciphers library
	, cipher_null_null
	, cipher_RC4_128_MD5
	, cipher_RC4_128_SHA1
	, cipher_AES128_SHA1
	, cipher_AES256_SHA1
	, cipher_AES128_SHA256
	, cipher_AES256_SHA256
	) where

import Data.Word
import Network.TLS.Struct (Version(..))
import Network.TLS.MAC
import qualified Data.Vector.Unboxed as Vector (fromList, toList)
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as B

import qualified Codec.Crypto.AES as AES
import qualified Crypto.Cipher.RC4 as RC4

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

data Cipher = Cipher
	{ cipherID           :: Word16
	, cipherName         :: String
	, cipherDigestSize   :: Word8
	, cipherKeySize      :: Word8
	, cipherIVSize       :: Word8
	, cipherKeyBlockSize :: Word8
	, cipherPaddingSize  :: Word8
	, cipherKeyExchange  :: CipherKeyExchangeType
	, cipherHMAC         :: B.ByteString -> B.ByteString -> B.ByteString
	, cipherF            :: CipherTypeFunctions
	, cipherMinVer       :: Maybe Version
	}

instance Show Cipher where
	show c = cipherName c

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

repack :: Int -> B.ByteString -> [B.ByteString]
repack bs x =
	if B.length x > bs
		then
			let (c1, c2) = B.splitAt bs x in
			B.pack (B.unpack c1) : repack 16 c2
		else
			[ x ]

lazyToStrict :: L.ByteString -> B.ByteString
lazyToStrict = B.concat . L.toChunks

aes128_cbc_encrypt :: Key -> IV -> B.ByteString -> B.ByteString
aes128_cbc_encrypt key iv d = lazyToStrict $ AES.crypt AES.CBC key iv AES.Encrypt d16
	where d16 = L.fromChunks $ repack 16 d

aes128_cbc_decrypt :: Key -> IV -> B.ByteString -> B.ByteString
aes128_cbc_decrypt key iv d = lazyToStrict $ AES.crypt AES.CBC key iv AES.Decrypt d16
	where d16 = L.fromChunks $ repack 16 d

aes256_cbc_encrypt :: Key -> IV -> B.ByteString -> B.ByteString
aes256_cbc_encrypt key iv d = lazyToStrict $ AES.crypt AES.CBC key iv AES.Encrypt d16
	where d16 = L.fromChunks $ repack 16 d

aes256_cbc_decrypt :: Key -> IV -> B.ByteString -> B.ByteString
aes256_cbc_decrypt key iv d = lazyToStrict $ AES.crypt AES.CBC key iv AES.Decrypt d16
	where d16 = L.fromChunks $ repack 32 d

toIV :: RC4.Ctx -> IV
toIV (v, x, y) = B.pack (x : y : Vector.toList v)

toCtx :: IV -> RC4.Ctx
toCtx iv =
	case B.unpack iv of
		x:y:l -> (Vector.fromList l, x, y)
		_     -> (Vector.fromList [], 0, 0)

initF_rc4 :: Key -> IV
initF_rc4 key     = toIV $ RC4.initCtx (B.unpack key)

encryptF_rc4 :: IV -> B.ByteString -> (B.ByteString, IV)
encryptF_rc4 iv d = (\(ctx, e) -> (e, toIV ctx)) $ RC4.encrypt (toCtx iv) d

decryptF_rc4 :: IV -> B.ByteString -> (B.ByteString, IV)
decryptF_rc4 iv e = (\(ctx, d) -> (d, toIV ctx)) $ RC4.decrypt (toCtx iv) e

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

{-
 - some builtin ciphers description
 -}

cipher_null_null :: Cipher
cipher_null_null = Cipher
	{ cipherID           = 0x0
	, cipherName         = "null-null"
	, cipherDigestSize   = 0
	, cipherKeySize      = 0
	, cipherIVSize       = 0
	, cipherKeyBlockSize = 0
	, cipherPaddingSize  = 0
	, cipherHMAC         = (\_ _ -> B.empty)
	, cipherKeyExchange  = CipherKeyExchangeRSA
	, cipherF            = CipherNoneF
	, cipherMinVer       = Nothing
	}

cipher_RC4_128_MD5 :: Cipher
cipher_RC4_128_MD5 = Cipher
	{ cipherID           = 0x04
	, cipherName         = "RSA-rc4-128-md5"
	, cipherDigestSize   = 16
	, cipherKeySize      = 16
	, cipherIVSize       = 0
	, cipherKeyBlockSize = 2 * (16 + 16 + 0)
	, cipherPaddingSize  = 0
	, cipherHMAC         = hmacMD5
	, cipherKeyExchange  = CipherKeyExchangeRSA
	, cipherF            = CipherStreamF initF_rc4 encryptF_rc4 decryptF_rc4
	, cipherMinVer       = Nothing
	}

cipher_RC4_128_SHA1 :: Cipher
cipher_RC4_128_SHA1 = Cipher
	{ cipherID           = 0x05
	, cipherName         = "RSA-rc4-128-sha1"
	, cipherDigestSize   = 20
	, cipherKeySize      = 16
	, cipherIVSize       = 0
	, cipherKeyBlockSize = 2 * (20 + 16 + 0)
	, cipherPaddingSize  = 0
	, cipherHMAC         = hmacSHA1
	, cipherKeyExchange  = CipherKeyExchangeRSA
	, cipherF            = CipherStreamF initF_rc4 encryptF_rc4 decryptF_rc4
	, cipherMinVer       = Nothing
	}

cipher_AES128_SHA1 :: Cipher
cipher_AES128_SHA1 = Cipher
	{ cipherID           = 0x2f
	, cipherName         = "RSA-aes128-sha1"
	, cipherDigestSize   = 20
	, cipherKeySize      = 16
	, cipherIVSize       = 16
	, cipherKeyBlockSize = 2 * (20 + 16 + 16)
	, cipherPaddingSize  = 16
	, cipherHMAC         = hmacSHA1
	, cipherKeyExchange  = CipherKeyExchangeRSA
	, cipherF            = CipherBlockF aes128_cbc_encrypt aes128_cbc_decrypt
	, cipherMinVer       = Just SSL3
	}

cipher_AES256_SHA1 :: Cipher
cipher_AES256_SHA1 = Cipher
	{ cipherID           = 0x35
	, cipherName         = "RSA-aes256-sha1"
	, cipherDigestSize   = 20
	, cipherKeySize      = 32
	, cipherIVSize       = 16
	, cipherKeyBlockSize = 2 * (20 + 32 + 16)
	, cipherPaddingSize  = 16
	, cipherHMAC         = hmacSHA1
	, cipherKeyExchange  = CipherKeyExchangeRSA
	, cipherF            = CipherBlockF aes256_cbc_encrypt aes256_cbc_decrypt
	, cipherMinVer       = Just SSL3
	}

cipher_AES128_SHA256 :: Cipher
cipher_AES128_SHA256 = Cipher
	{ cipherID           = 0x3c
	, cipherName         = "RSA-aes128-sha256"
	, cipherDigestSize   = 32
	, cipherKeySize      = 16
	, cipherIVSize       = 16
	, cipherKeyBlockSize = 2 * (32 + 16 + 16)
	, cipherPaddingSize  = 16
	, cipherHMAC         = hmacSHA256
	, cipherKeyExchange  = CipherKeyExchangeRSA
	, cipherF            = CipherBlockF aes128_cbc_encrypt aes128_cbc_decrypt
	, cipherMinVer       = Just TLS12
	}

cipher_AES256_SHA256 :: Cipher
cipher_AES256_SHA256 = Cipher
	{ cipherID           = 0x3d
	, cipherName         = "RSA-aes256-sha256"
	, cipherDigestSize   = 32
	, cipherKeySize      = 32
	, cipherIVSize       = 16
	, cipherKeyBlockSize = 2 * (32 + 32 + 16)
	, cipherPaddingSize  = 16
	, cipherHMAC         = hmacSHA256
	, cipherKeyExchange  = CipherKeyExchangeRSA
	, cipherF            = CipherBlockF aes256_cbc_encrypt aes256_cbc_decrypt
	, cipherMinVer       = Just TLS12
	}
