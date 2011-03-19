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
	-- * Versions
	, Version(..)
	-- * Errors
	, TLSError(..)
	) where

import Network.TLS.Struct (Version(..), TLSError(..))
import Network.TLS.Crypto (PrivateKey(..))
import Network.TLS.Cipher (Cipher(..))
import Network.TLS.Compression (Compression(..), nullCompression)
import Network.TLS.SRandom (makeSRandomGen, SRandomGen)
import Network.TLS.Core
