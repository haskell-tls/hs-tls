-- this is probably not a very good random interface, nor it has any good randomness capability.
-- the module is just here until a really good CPRNG implementation come up..
module Network.TLS.SRandom
	( SRandomGen
	, makeSRandomGen
	, getRandomBytes
	) where

import Data.Word
import Control.Arrow (first)
import Crypto.Random
import System.Random
import System.Crypto.Random (getEntropy)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Codec.Crypto.AES as AES
import Data.Bits (xor, shiftL)
import Data.Serialize

{-
 - the following CPRNG is an AES cbc based counter system.
 -
 - 16 bytes IV, 16 bytes counter, 32 bytes key
 - (IV `xor` counter) `aes` key -> 16 bytes output
 -}

data Word128 = Word128 !Word64 !Word64

data SRandomGen = RNG !ByteString !Word128 !ByteString

instance Show SRandomGen where
	show _ = "srandomgen[..]"

put128 :: Word128 -> ByteString
put128 (Word128 a b) = runPut (putWord64host a >> putWord64host b)

get128 :: ByteString -> Word128
get128 = either (\_ -> Word128 0 0) id . runGet (getWord64host >>= \a -> (getWord64host >>= \b -> return $ Word128 a b))

add1 :: Word128 -> Word128
add1 (Word128 a b) = if b == 0xffffffffffffffff then Word128 (a+1) 0 else Word128 a (b+1)

toBigInt :: Word128 -> Integer
toBigInt (Word128 a b) = ((fromIntegral a) `shiftL` 64) + fromIntegral b

make :: B.ByteString -> Either GenError SRandomGen
make b
	| B.length b < 64 = Left NotEnoughEntropy
	| otherwise       = Right $ RNG iv (get128 cnt) key
		where
			key          = B.take 32 left2
			(cnt, left2) = B.splitAt 16 left1
			(iv, left1)  = B.splitAt 16 b

chunkSize :: Int
chunkSize = 16

nextChunk :: SRandomGen -> (ByteString, SRandomGen)
nextChunk (RNG iv counter key) = (chunk, newrng)
	where
		newrng = RNG chunk (add1 counter) key
		chunk  = AES.crypt' AES.CBC key iv AES.Encrypt bytes
		bytes  = iv `bxor` (put128 counter)
		bxor a b = B.pack $ B.zipWith xor a b

makeSRandomGen :: IO (Either GenError SRandomGen)
makeSRandomGen = getEntropy 64 >>= return . make

getRandomBytes :: SRandomGen -> Int -> (ByteString, SRandomGen)
getRandomBytes rng n =
	let list = helper rng n in
	(B.concat $ map fst list, snd $ last list)
	where
		helper _ 0 = []
		helper g i =
			let (b, g') = nextChunk g in
			if chunkSize >= i
				then [ (B.take i b, g') ]
				else (b, g') : helper g' (i-chunkSize)

instance CryptoRandomGen SRandomGen where
	newGen           = make
	genSeedLength    = 64
	genBytes len rng = Right $ getRandomBytes rng len
	reseed b rng     = Right rng

instance RandomGen SRandomGen where
	split _  = error "split not supported on SRandomGen"
	next rng = (fromIntegral $ toBigInt w, rng')
		where
			(w, rng') = first get128 $ nextChunk rng

