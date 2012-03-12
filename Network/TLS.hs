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

	-- * Backend abstraction
	, TLSBackend(..)

	-- * Context object
	, TLSCtx
	, ctxConnection

	-- * Creating a context
	, client
	, server

	-- * Initialisation and Termination of context
	, bye
	, handshake

	-- * High level API
	, sendData
	, recvData
	, recvData'

	-- * Crypto Key
	, PrivateKey(..)
	-- * Compressions & Predefined compressions
	, CompressionC(..)
	, Compression(..)
	, nullCompression
	-- * Ciphers & Predefined ciphers
	, Cipher(..)
	, Bulk(..)
	-- * Versions
	, Version(..)
	-- * Errors
	, TLSError(..)
	-- * Exceptions
	, HandshakeFailed(..)
	, ConnectionNotEstablished(..)
	) where

import Network.TLS.Struct (Version(..), TLSError(..))
import Network.TLS.Crypto (PrivateKey(..))
import Network.TLS.Cipher (Cipher(..), Bulk(..))
import Network.TLS.Compression (CompressionC(..), Compression(..), nullCompression)
import Network.TLS.Context
import Network.TLS.Core
