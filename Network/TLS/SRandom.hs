-- this is probably not a very good random interface, nor it has any good randomness capability.
-- the module is just here until a really good CPRNG implementation come up..
module Network.TLS.SRandom
	( SRandomGen
	, makeSRandomGen
	, getRandomByte
	, getRandomBytes
	) where

import System.Random
import Control.Arrow (first)
import Data.Word

type SRandomGen = StdGen

makeSRandomGen :: Int -> SRandomGen
makeSRandomGen i = mkStdGen i

getRandomByte :: SRandomGen -> (Word8, SRandomGen)
getRandomByte rng = first fromIntegral $ next rng

getRandomBytes :: SRandomGen -> Int -> ([Word8], SRandomGen)
getRandomBytes rng n =
	let list = helper rng n in
	(map fst list, snd $ last list)
	where
		helper _ 0 = []
		helper g i =
			let (b, g') = getRandomByte g in
			(b, g') : helper g' (i-1)
