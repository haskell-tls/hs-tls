module Network.TLS.MAC
	( hmacMD5
	, hmacSHA1
	, hmacSHA256
	, prf_MD5
	, prf_SHA1
	, prf_MD5SHA1
	) where

import qualified Data.CryptoHash.MD5 as MD5
import qualified Data.CryptoHash.SHA1 as SHA1
import qualified Data.CryptoHash.SHA256 as SHA256
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as B
import Data.ByteString.Lazy (ByteString)
import Data.Bits (xor)

lazyOfStrict :: B.ByteString -> ByteString
lazyOfStrict b = L.fromChunks [ b ]

hmac :: (ByteString -> ByteString) -> Int -> ByteString -> ByteString -> ByteString
hmac f bl secret msg =
	f $! L.append opad (f $! L.append ipad msg)
	where
		opad = L.map (xor 0x5c) k'
		ipad = L.map (xor 0x36) k'

		k' = L.append kt pad
			where
			kt  = if L.length secret > fromIntegral bl then f secret else secret
			pad = L.replicate (fromIntegral bl - L.length kt) 0

hmacMD5 :: ByteString -> ByteString -> ByteString
hmacMD5 secret msg = hmac (lazyOfStrict . MD5.hashlazy) 64 secret msg

hmacSHA1 :: ByteString -> ByteString -> ByteString
hmacSHA1 secret msg = hmac (lazyOfStrict . SHA1.hashlazy) 64 secret msg

hmacSHA256 :: ByteString -> ByteString -> ByteString
hmacSHA256 secret msg = hmac (lazyOfStrict . SHA256.hashlazy) 64 secret msg

hmacIter :: (ByteString -> ByteString -> ByteString) -> ByteString -> ByteString -> ByteString -> Int -> [ByteString]
hmacIter f secret seed aprev len =
	let an = f secret aprev in
	let out = f secret (L.concat [an, seed]) in
	let digestsize = fromIntegral $ L.length out in
	if digestsize >= len
		then [ L.take (fromIntegral len) out ]
		else out : hmacIter f secret seed an (len - digestsize)

prf_SHA1 :: ByteString -> ByteString -> Int -> ByteString
prf_SHA1 secret seed len = L.concat $ hmacIter hmacSHA1 secret seed seed len

prf_MD5 :: ByteString -> ByteString -> Int -> ByteString
prf_MD5 secret seed len = L.concat $ hmacIter hmacMD5 secret seed seed len

prf_MD5SHA1 :: ByteString -> ByteString -> Int -> ByteString
prf_MD5SHA1 secret seed len =
	L.pack $ L.zipWith xor (prf_MD5 s1 seed len) (prf_SHA1 s2 seed len)
	where
		slen  = L.length secret
		s1    = L.take (slen `div` 2 + slen `mod` 2) secret
		s2    = L.drop (slen `div` 2) secret
