-- |
-- Module      : Network.TLS.Wire
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Wire module is a specialized marshalling/unmarshalling package related to the TLS protocol.
-- all multibytes values are written as big endian.
--
module Network.TLS.Wire
	( Get
	, runGet
	, remaining
	, getWord8
	, getWords8
	, getWord16
	, getWords16
	, getWord24
	, getBytes
	, processBytes
	, isEmpty
	, Put
	, runPut
	, putWord8
	, putWords8
	, putWord16
	, putWords16
	, putWord24
	, putBytes
	, encodeWord16
	, encodeWord64
	) where

import Data.Serialize.Get hiding (runGet)
import qualified Data.Serialize.Get as G
import Data.Serialize.Put
import Control.Applicative ((<$>))
import Control.Monad.Error
import Data.Word
import Data.Bits
import Network.TLS.Struct

runGet :: String -> Get a -> Bytes -> Either String a
runGet lbl f = G.runGet (label lbl f)

getWords8 :: Get [Word8]
getWords8 = getWord8 >>= \lenb -> replicateM (fromIntegral lenb) getWord8

getWord16 :: Get Word16
getWord16 = getWord16be

getWords16 :: Get [Word16]
getWords16 = getWord16 >>= \lenb -> replicateM (fromIntegral lenb `div` 2) getWord16

getWord24 :: Get Int
getWord24 = do
	a <- fromIntegral <$> getWord8
	b <- fromIntegral <$> getWord8
	c <- fromIntegral <$> getWord8
	return $ (a `shiftL` 16) .|. (b `shiftL` 8) .|. c

processBytes :: Int -> Get a -> Get a
processBytes i f = isolate i f

putWords8 :: [Word8] -> Put
putWords8 l = do
	putWord8 $ fromIntegral (length l)
	mapM_ putWord8 l

putWord16 :: Word16 -> Put
putWord16 = putWord16be

putWords16 :: [Word16] -> Put
putWords16 l = do
	putWord16 $ 2 * (fromIntegral $ length l)
	mapM_ putWord16 l

putWord24 :: Int -> Put
putWord24 i = do
	let a = fromIntegral ((i `shiftR` 16) .&. 0xff)
	let b = fromIntegral ((i `shiftR` 8) .&. 0xff)
	let c = fromIntegral (i .&. 0xff)
	mapM_ putWord8 [a,b,c]

putBytes :: Bytes -> Put
putBytes = putByteString

encodeWord16 :: Word16 -> Bytes
encodeWord16 = runPut . putWord16

encodeWord64 :: Word64 -> Bytes
encodeWord64 = runPut . putWord64be
