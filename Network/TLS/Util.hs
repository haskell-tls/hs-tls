module Network.TLS.Util
	( sub
	, takelast
	, partition3
	, partition6
	) where

import Network.TLS.Struct (Bytes)
import qualified Data.ByteString as B

sub :: Bytes -> Int -> Int -> Maybe Bytes
sub b offset len
	| B.length b < offset + len = Nothing
	| otherwise                 = Just $ B.take len $ snd $ B.splitAt offset b

takelast :: Int -> Bytes -> Maybe Bytes
takelast i b
	| B.length b >= i = sub b (B.length b - i) i
	| otherwise       = Nothing

partition3 :: Bytes -> (Int,Int,Int) -> Maybe (Bytes, Bytes, Bytes)
partition3 bytes (d1,d2,d3) = if B.length bytes /= s then Nothing else Just (p1,p2,p3)
	where
		s        = sum [d1,d2,d3]
		(p1, r1) = B.splitAt d1 bytes
		(p2, r2) = B.splitAt d2 r1
		(p3, _)  = B.splitAt d3 r2

partition6 :: Bytes -> (Int,Int,Int,Int,Int,Int) -> Maybe (Bytes, Bytes, Bytes, Bytes, Bytes, Bytes)
partition6 bytes (d1,d2,d3,d4,d5,d6) = if B.length bytes /= s then Nothing else Just (p1,p2,p3,p4,p5,p6)
	where
		s        = sum [d1,d2,d3,d4,d5,d6]
		(p1, r1) = B.splitAt d1 bytes
		(p2, r2) = B.splitAt d2 r1
		(p3, r3) = B.splitAt d3 r2
		(p4, r4) = B.splitAt d4 r3
		(p5, r5) = B.splitAt d5 r4
		(p6, _)  = B.splitAt d6 r5
