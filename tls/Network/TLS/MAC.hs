module Network.TLS.MAC (
    macSSL,
    hmac,
    prf_MD5,
    prf_SHA1,
    prf_SHA256,
    prf_TLS,
    prf_MD5SHA1,
    PRF,
) where

import Data.ByteArray (ByteArray, ByteArrayAccess)
import qualified Data.ByteArray as BA
import Foreign.Ptr
import Foreign.Storable

import Network.TLS.Crypto
import Network.TLS.Imports
import Network.TLS.Types

type HMAC = Secret -> ByteString -> Secret

macSSL :: Hash -> HMAC
macSSL alg secret msg =
    f $
        BA.concat
            [ secret
            , BA.replicate padLen 0x5c
            , f $ BA.concat [secret, BA.replicate padLen 0x36, BA.convert msg]
            ]
  where
    padLen = case alg of
        MD5 -> 48
        SHA1 -> 40
        _ -> error ("internal error: macSSL called with " ++ show alg)
    f = hash alg

hmac :: (ByteArray ba, ByteArrayAccess ba) => Hash -> ba -> ByteString -> ba
hmac alg secret msg = f $ BA.append opad (f $ BA.append ipad $ BA.convert msg)
  where
    opad = mapBA (0x5c `xor`) k'
    ipad = mapBA (0x36 `xor`) k'

    f = hash alg
    bl = hashBlockSize alg

    k' = BA.append kt pad
      where
        kt = if BA.length secret > fromIntegral bl then f secret else secret
        pad = BA.replicate (fromIntegral bl - BA.length kt) 0

hmacIter
    :: HMAC -> Secret -> ByteString -> ByteString -> Int -> [Secret]
hmacIter f secret seed aprev len =
    let an = f secret aprev
     in let out = f secret (BA.concat [an, BA.convert seed])
         in let digestsize = BA.length out
             in if digestsize >= len
                    then [BA.take (fromIntegral len) out]
                    else out : hmacIter f secret seed (BA.convert an) (len - digestsize)

type PRF = Secret -> ByteString -> Int -> Secret

prf_SHA1 :: PRF
prf_SHA1 secret seed len = BA.concat $ hmacIter (hmac SHA1) secret seed seed len

prf_MD5 :: PRF
prf_MD5 secret seed len = BA.concat $ hmacIter (hmac MD5) secret seed seed len

prf_MD5SHA1 :: PRF
prf_MD5SHA1 secret seed len =
    BA.xor (prf_MD5 s1 seed len) (prf_SHA1 s2 seed len)
  where
    slen = BA.length secret
    s1 = BA.take (slen `div` 2 + slen `mod` 2) secret
    s2 = BA.drop (slen `div` 2) secret

prf_SHA256 :: PRF
prf_SHA256 secret seed len = BA.concat $ hmacIter (hmac SHA256) secret seed seed len

-- | For now we ignore the version, but perhaps some day the PRF will depend
-- not only on the cipher PRF algorithm, but also on the protocol version.
prf_TLS :: Version -> Hash -> PRF
prf_TLS _ halg secret seed len =
    BA.concat $ hmacIter (hmac halg) secret seed seed len

mapBA :: (ByteArrayAccess ba, ByteArray ba) => (Word8 -> Word8) -> ba -> ba
mapBA f ba = BA.copyAndFreeze ba $ loop 0
  where
    len = BA.length ba
    loop i ptr
        | i == len = return ()
        | otherwise = do
            let ptr' = ptr `plusPtr` i
            x <- peek ptr'
            poke ptr' $ f x
            loop (i + 1) ptr
