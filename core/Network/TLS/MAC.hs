-- |
-- Module      : Network.TLS.MAC
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.MAC
    ( macSSL
    , hmac
    , prf_MD5
    , prf_SHA1
    , prf_SHA256
    , prf_TLS
    , prf_MD5SHA1
    ) where

import Network.TLS.Crypto
import Network.TLS.Types
import Network.TLS.Imports
import qualified Data.ByteArray as B (xor)
import qualified Data.ByteString as B

type HMAC = ByteString -> ByteString -> ByteString

macSSL :: Hash -> HMAC
macSSL alg secret msg =
    f $! B.concat
        [ secret
        , B.replicate padLen 0x5c
        , f $! B.concat [ secret, B.replicate padLen 0x36, msg ]
        ]
  where
    padLen = case alg of
        MD5  -> 48
        SHA1 -> 40
        _    -> error ("internal error: macSSL called with " ++ show alg)
    f = hash alg

hmac :: Hash -> HMAC
hmac alg secret msg = f $! B.append opad (f $! B.append ipad msg)
  where opad = B.map (xor 0x5c) k'
        ipad = B.map (xor 0x36) k'

        f = hash alg
        bl = hashBlockSize alg

        k' = B.append kt pad
          where kt  = if B.length secret > fromIntegral bl then f secret else secret
                pad = B.replicate (fromIntegral bl - B.length kt) 0

hmacIter :: HMAC -> ByteString -> ByteString -> ByteString -> Int -> [ByteString]
hmacIter f secret seed aprev len =
    let an = f secret aprev in
    let out = f secret (B.concat [an, seed]) in
    let digestsize = B.length out in
    if digestsize >= len
        then [ B.take (fromIntegral len) out ]
        else out : hmacIter f secret seed an (len - digestsize)

prf_SHA1 :: ByteString -> ByteString -> Int -> ByteString
prf_SHA1 secret seed len = B.concat $ hmacIter (hmac SHA1) secret seed seed len

prf_MD5 :: ByteString -> ByteString -> Int -> ByteString
prf_MD5 secret seed len = B.concat $ hmacIter (hmac MD5) secret seed seed len

prf_MD5SHA1 :: ByteString -> ByteString -> Int -> ByteString
prf_MD5SHA1 secret seed len =
    B.xor (prf_MD5 s1 seed len) (prf_SHA1 s2 seed len)
  where slen  = B.length secret
        s1    = B.take (slen `div` 2 + slen `mod` 2) secret
        s2    = B.drop (slen `div` 2) secret

prf_SHA256 :: ByteString -> ByteString -> Int -> ByteString
prf_SHA256 secret seed len = B.concat $ hmacIter (hmac SHA256) secret seed seed len

-- | For now we ignore the version, but perhaps some day the PRF will depend
-- not only on the cipher PRF algorithm, but also on the protocol version.
prf_TLS :: Version -> Hash -> ByteString -> ByteString -> Int -> ByteString
prf_TLS _ halg secret seed len =
    B.concat $ hmacIter (hmac halg) secret seed seed len
