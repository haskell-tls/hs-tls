-- |
-- Module      : Network.TLS.Extra.Cipher
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Extra.Cipher
	(
	  ciphersuite_all
	, ciphersuite_medium
	, ciphersuite_strong
	, ciphersuite_unencrypted
	, cipher_null_null
	, cipher_null_SHA1
	, cipher_null_MD5
	, cipher_RC4_128_MD5
	, cipher_RC4_128_SHA1
	, cipher_AES128_SHA1
	, cipher_AES256_SHA1
	, cipher_AES128_SHA256
	, cipher_AES256_SHA256
	) where

import qualified Data.Vector.Unboxed as Vector (fromList, toList)
import qualified Data.ByteString as B

import Network.TLS (Version(..))
import Network.TLS.Cipher
import qualified Crypto.Cipher.AES as AES
import qualified Crypto.Cipher.RC4 as RC4

import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.MD5 as MD5

aes128_cbc_encrypt :: Key -> IV -> B.ByteString -> B.ByteString
aes128_cbc_encrypt key iv d = AES.encryptCBC pkey iv d
	where (Right pkey) = AES.initKey128 key

aes128_cbc_decrypt :: Key -> IV -> B.ByteString -> B.ByteString
aes128_cbc_decrypt key iv d = AES.decryptCBC pkey iv d
	where (Right pkey) = AES.initKey128 key

aes256_cbc_encrypt :: Key -> IV -> B.ByteString -> B.ByteString
aes256_cbc_encrypt key iv d = AES.encryptCBC pkey iv d
	where (Right pkey) = AES.initKey256 key

aes256_cbc_decrypt :: Key -> IV -> B.ByteString -> B.ByteString
aes256_cbc_decrypt key iv d = AES.decryptCBC pkey iv d
	where (Right pkey) = AES.initKey256 key

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


ciphersuite_all :: [Cipher]
ciphersuite_all =
	[ cipher_AES128_SHA256, cipher_AES256_SHA256
	, cipher_AES128_SHA1,   cipher_AES256_SHA1
	, cipher_RC4_128_SHA1,  cipher_RC4_128_MD5
	]

ciphersuite_medium :: [Cipher]
ciphersuite_medium = [cipher_RC4_128_MD5, cipher_RC4_128_SHA1, cipher_AES128_SHA1, cipher_AES256_SHA1]

ciphersuite_strong :: [Cipher]
ciphersuite_strong = [cipher_AES256_SHA256, cipher_AES256_SHA1]

ciphersuite_unencrypted :: [Cipher]
ciphersuite_unencrypted = [cipher_null_MD5, cipher_null_SHA1]

cipher_null_null :: Cipher
cipher_null_null = Cipher
	{ cipherID           = 0x0
	, cipherName         = "null-null"
	, cipherDigestSize   = 0
	, cipherKeySize      = 0
	, cipherIVSize       = 0
	, cipherKeyBlockSize = 0
	, cipherPaddingSize  = 0
	, cipherMACHash      = (const B.empty)
	, cipherKeyExchange  = CipherKeyExchangeRSA
	, cipherF            = CipherNoneF
	, cipherMinVer       = Nothing
	}

cipher_null_MD5 :: Cipher
cipher_null_MD5 = Cipher
	{ cipherID           = 0x1
	, cipherName         = "RSA-null-MD5"
	, cipherDigestSize   = 16
	, cipherKeySize      = 0
	, cipherIVSize       = 0
	, cipherKeyBlockSize = 2 * (16 + 0 + 0)
	, cipherPaddingSize  = 0
	, cipherMACHash      = MD5.hash
	, cipherKeyExchange  = CipherKeyExchangeRSA
	, cipherF            = CipherNoneF
	, cipherMinVer       = Nothing
	}

cipher_null_SHA1 :: Cipher
cipher_null_SHA1 = Cipher
	{ cipherID           = 0x2
	, cipherName         = "RSA-null-SHA1"
	, cipherDigestSize   = 20
	, cipherKeySize      = 0
	, cipherIVSize       = 0
	, cipherKeyBlockSize = 2 * (20 + 0 + 0)
	, cipherPaddingSize  = 0
	, cipherMACHash      = SHA1.hash
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
	, cipherMACHash      = MD5.hash
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
	, cipherMACHash      = SHA1.hash
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
	, cipherMACHash      = SHA1.hash
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
	, cipherMACHash      = SHA1.hash
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
	, cipherMACHash      = SHA256.hash
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
	, cipherMACHash      = SHA256.hash
	, cipherKeyExchange  = CipherKeyExchangeRSA
	, cipherF            = CipherBlockF aes256_cbc_encrypt aes256_cbc_decrypt
	, cipherMinVer       = Just TLS12
	}

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
