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
import qualified Data.ByteString as B
import Data.ByteString (ByteString)
import Data.Bits (xor)

hmac :: (ByteString -> ByteString) -> Int -> ByteString -> ByteString -> ByteString
hmac f bl secret msg =
	f $! B.append opad (f $! B.append ipad msg)
	where
		opad = B.map (xor 0x5c) k'
		ipad = B.map (xor 0x36) k'

		k' = B.append kt pad
			where
			kt  = if B.length secret > fromIntegral bl then f secret else secret
			pad = B.replicate (fromIntegral bl - B.length kt) 0

hmacMD5 :: ByteString -> ByteString -> ByteString
hmacMD5 secret msg = hmac MD5.hash 64 secret msg

hmacSHA1 :: ByteString -> ByteString -> ByteString
hmacSHA1 secret msg = hmac SHA1.hash 64 secret msg

hmacSHA256 :: ByteString -> ByteString -> ByteString
hmacSHA256 secret msg = hmac SHA256.hash 64 secret msg

hmacIter :: (ByteString -> ByteString -> ByteString) -> ByteString -> ByteString -> ByteString -> Int -> [ByteString]
hmacIter f secret seed aprev len =
	let an = f secret aprev in
	let out = f secret (B.concat [an, seed]) in
	let digestsize = fromIntegral $ B.length out in
	if digestsize >= len
		then [ B.take (fromIntegral len) out ]
		else out : hmacIter f secret seed an (len - digestsize)

prf_SHA1 :: ByteString -> ByteString -> Int -> ByteString
prf_SHA1 secret seed len = B.concat $ hmacIter hmacSHA1 secret seed seed len

prf_MD5 :: ByteString -> ByteString -> Int -> ByteString
prf_MD5 secret seed len = B.concat $ hmacIter hmacMD5 secret seed seed len

prf_MD5SHA1 :: ByteString -> ByteString -> Int -> ByteString
prf_MD5SHA1 secret seed len =
	B.pack $ B.zipWith xor (prf_MD5 s1 seed len) (prf_SHA1 s2 seed len)
	where
		slen  = B.length secret
		s1    = B.take (slen `div` 2 + slen `mod` 2) secret
		s2    = B.drop (slen `div` 2) secret
