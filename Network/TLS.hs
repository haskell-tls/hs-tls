-- |
-- Module      : Network.TLS
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS
	(
	-- * Context configuration
	  TLSParams(..)
	, TLSLogging(..)
	, TLSCertificateUsage(..)
	, TLSCertificateRejectReason(..)
	, defaultParams
	, defaultLogging

	-- * Context object
	, TLSCtx
	, ctxHandle

	-- * Creating a context
	, client
	, server

	-- * Initialisation and Termination of context
	, bye
	, handshake

	-- * High level API
	, sendData
	, recvData

	-- * Crypto Key
	, PrivateKey(..)
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
import Network.TLS.Core
