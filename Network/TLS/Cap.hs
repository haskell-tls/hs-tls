-- |
-- Module      : Network.TLS.Cap
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--

module Network.TLS.Cap
	( hasHelloExtensions
	, hasExplicitBlockIV
	) where

import Network.TLS.Struct

hasHelloExtensions, hasExplicitBlockIV :: Version -> Bool

hasHelloExtensions ver = ver >= TLS12
hasExplicitBlockIV ver = ver >= TLS11
