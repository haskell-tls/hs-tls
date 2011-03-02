{-# OPTIONS_HADDOCK hide #-}
-- |
-- Module      : Network.TLS.Compression
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Compression
	( Compression(..)
	, nullCompression
	) where

import Data.Word
import Data.ByteString (ByteString)

-- | Compression algorithm
data Compression = Compression
	{ compressionID :: Word8
	, compressionFct :: (ByteString -> ByteString)
	}

instance Show Compression where
	show = show . compressionID

-- | default null compression
nullCompression :: Compression
nullCompression = Compression { compressionID = 0, compressionFct = id }
