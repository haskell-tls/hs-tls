-- |
-- Module      : Network.TLS
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS
	(
	module Network.TLS.Core
	-- * Crypto Key
	, PrivateKey(..)
	-- * Crypto RNG
	, makeSRandomGen, SRandomGen
	-- * Compressions & Predefined compressions
	, Compression
	, nullCompression
	-- * Ciphers & Predefined ciphers
	, Cipher
	, cipher_null_null
	, cipher_null_SHA1
	, cipher_null_MD5
	, cipher_RC4_128_MD5
	, cipher_RC4_128_SHA1
	, cipher_AES128_SHA1
	, cipher_AES256_SHA1
	, cipher_AES128_SHA256
	, cipher_AES256_SHA256
	-- * Versions
	, Version(..)
	-- * Errors
	, TLSError(..)
	) where

import Network.TLS.Struct (Version(..), TLSError(..))
import Network.TLS.Crypto (PrivateKey(..))
import Network.TLS.Cipher (Cipher(..), cipher_null_null , cipher_null_SHA1 , cipher_null_MD5 , cipher_RC4_128_MD5 , cipher_RC4_128_SHA1 , cipher_AES128_SHA1 , cipher_AES256_SHA1 , cipher_AES128_SHA256 , cipher_AES256_SHA256)
import Network.TLS.Compression (Compression(..), nullCompression)
import Network.TLS.SRandom (makeSRandomGen, SRandomGen)
import Network.TLS.Core
