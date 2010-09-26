module Network.TLS.Util
	( sub
	, takelast
	, partition3
	, partition6
	) where

import Network.TLS.Struct (Bytes)
import Network.TLS.Wire
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
partition3 bytes (d1,d2,d3) = either (const Nothing) Just $ (flip runGet) bytes $ do
	p1 <- getBytes d1
	p2 <- getBytes d2
	p3 <- getBytes d3
	return (p1,p2,p3)

partition6 :: Bytes -> (Int,Int,Int,Int,Int,Int) -> Maybe (Bytes, Bytes, Bytes, Bytes, Bytes, Bytes)
partition6 bytes (d1,d2,d3,d4,d5,d6) = either (const Nothing) Just $ (flip runGet) bytes $ do
	p1 <- getBytes d1
	p2 <- getBytes d2
	p3 <- getBytes d3
	p4 <- getBytes d4
	p5 <- getBytes d5
	p6 <- getBytes d6
	return (p1,p2,p3,p4,p5,p6)
