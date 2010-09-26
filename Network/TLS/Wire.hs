{-# LANGUAGE GeneralizedNewtypeDeriving,FlexibleInstances #-}

-- |
-- Module      : Network.TLS.Wire
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Wire module is a specialized Binary package related to the TLS protocol.
-- all multibytes values are written as big endian.
--
module Network.TLS.Wire
	( Get
	, runGet
	, remaining
	, bytesRead
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
	, encodeWord64
	) where

import qualified Data.Binary.Get as G
import qualified Data.Binary.Put as P
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Control.Applicative ((<$>))
import Control.Monad.Error
import Data.Word
import Data.Bits
import Network.TLS.Struct

instance Error TLSError where
	noMsg = Error_Misc ""
	strMsg = Error_Misc

newtype Get a = GE { runGE :: ErrorT TLSError G.Get a }
	deriving (Monad, MonadError TLSError)

instance Functor Get where
	fmap f = GE . fmap f . runGE

liftGet :: G.Get a -> Get a
liftGet = GE . lift

runGet :: Get a -> Bytes -> Either TLSError a
runGet f b = G.runGet (runErrorT (runGE f)) (L.fromChunks [b])

remaining :: Get Int
remaining = fromIntegral <$> liftGet G.remaining

bytesRead :: Get Int
bytesRead = fromIntegral <$> liftGet G.bytesRead

getWord8 :: Get Word8
getWord8 = liftGet G.getWord8

getWords8 :: Get [Word8]
getWords8 = getWord8 >>= \lenb -> replicateM (fromIntegral lenb) getWord8

getWord16 :: Get Word16
getWord16 = liftGet G.getWord16be

getWords16 :: Get [Word16]
getWords16 = getWord16 >>= \lenb -> replicateM (fromIntegral lenb `div` 2) getWord16

getWord24 :: Get Int
getWord24 = do
	a <- fromIntegral <$> getWord8
	b <- fromIntegral <$> getWord8
	c <- fromIntegral <$> getWord8
	return $ (a `shiftL` 16) .|. (b `shiftL` 8) .|. c

getBytes :: Int -> Get Bytes
getBytes i = liftGet $ G.getBytes i

processBytes :: Int -> Get a -> Get a
processBytes i f = do
	r1 <- bytesRead
	ret <- f
	r2 <- bytesRead
	if r2 == (r1 + i)
		then return ret
		else throwError (Error_Internal_Packet_ByteProcessed r1 r2 i)
	
isEmpty :: Get Bool
isEmpty = liftGet G.isEmpty

type Put = P.Put

putWord8 :: Word8 -> Put
putWord8 = P.putWord8

putWords8 :: [Word8] -> Put
putWords8 l = do
	P.putWord8 $ fromIntegral (length l)
	mapM_ P.putWord8 l

putWord16 :: Word16 -> Put
putWord16 = P.putWord16be

putWords16 :: [Word16] -> Put
putWords16 l = do
	putWord16 $ 2 * (fromIntegral $ length l)
	mapM_ putWord16 l

putWord24 :: Int -> Put
putWord24 i = do
	let a = fromIntegral ((i `shiftR` 16) .&. 0xff)
	let b = fromIntegral ((i `shiftR` 8) .&. 0xff)
	let c = fromIntegral (i .&. 0xff)
	mapM_ P.putWord8 [a,b,c]

putBytes :: Bytes -> Put
putBytes = P.putByteString

lazyToBytes :: L.ByteString -> Bytes
lazyToBytes = B.concat . L.toChunks

runPut :: Put -> Bytes
runPut = lazyToBytes . P.runPut

encodeWord64 :: Word64 -> Bytes
encodeWord64 = runPut . P.putWord64be
