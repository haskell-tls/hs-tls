{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE ExistentialQuantification #-}
-- |
-- Module      : Network.TLS.Compression
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Compression
    ( CompressionC(..)
    , Compression(..)
    , CompressionID
    , nullCompression
    , NullCompression

    -- * member redefined for the class abstraction
    , compressionID
    , compressionDeflate
    , compressionInflate

    -- * helper
    , compressionIntersectID
    ) where

import Network.TLS.Types (CompressionID)
import Network.TLS.Imports
import Control.Arrow (first)

-- | supported compression algorithms need to be part of this class
class CompressionC a where
    compressionCID      :: a -> CompressionID
    compressionCDeflate :: a -> ByteString -> (a, ByteString)
    compressionCInflate :: a -> ByteString -> (a, ByteString)

-- | every compression need to be wrapped in this, to fit in structure
data Compression = forall a . CompressionC a => Compression a

-- | return the associated ID for this algorithm
compressionID :: Compression -> CompressionID
compressionID (Compression c) = compressionCID c

-- | deflate (compress) a bytestring using a compression context and return the result
-- along with the new compression context.
compressionDeflate :: ByteString -> Compression -> (Compression, ByteString)
compressionDeflate bytes (Compression c) = first Compression $ compressionCDeflate c bytes

-- | inflate (decompress) a bytestring using a compression context and return the result
-- along the new compression context.
compressionInflate :: ByteString -> Compression -> (Compression, ByteString)
compressionInflate bytes (Compression c) = first Compression $ compressionCInflate c bytes

instance Show Compression where
    show = show . compressionID
instance Eq Compression where
    (==) c1 c2 = compressionID c1 == compressionID c2

-- | intersect a list of ids commonly given by the other side with a list of compression
-- the function keeps the list of compression in order, to be able to find quickly the prefered
-- compression.
compressionIntersectID :: [Compression] -> [Word8] -> [Compression]
compressionIntersectID l ids = filter (\c -> compressionID c `elem` ids) l

-- | This is the default compression which is a NOOP.
data NullCompression = NullCompression

instance CompressionC NullCompression where
    compressionCID _        = 0
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

-- | default null compression
nullCompression :: Compression
nullCompression = Compression NullCompression
