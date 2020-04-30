{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Network.TLS.KeySchedule
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.KeySchedule
    ( hkdfExtract
    , hkdfExpandLabel
    , deriveSecret
    ) where

import qualified Crypto.Hash as H
import Crypto.KDF.HKDF
import Data.ByteArray (convert)
import qualified Data.ByteString as BS
import Network.TLS.Crypto
import Network.TLS.Wire
import Network.TLS.Imports

----------------------------------------------------------------

-- | @HKDF-Extract@ function.  Returns the pseudorandom key (PRK) from salt and
-- input keying material (IKM).
hkdfExtract :: Hash -> ByteString -> ByteString -> ByteString
hkdfExtract SHA1   salt ikm = convert (extract salt ikm :: PRK H.SHA1)
hkdfExtract SHA256 salt ikm = convert (extract salt ikm :: PRK H.SHA256)
hkdfExtract SHA384 salt ikm = convert (extract salt ikm :: PRK H.SHA384)
hkdfExtract SHA512 salt ikm = convert (extract salt ikm :: PRK H.SHA512)
hkdfExtract _ _ _           = error "hkdfExtract: unsupported hash"

----------------------------------------------------------------

deriveSecret :: Hash -> ByteString -> ByteString -> ByteString -> ByteString
deriveSecret h secret label hashedMsgs =
    hkdfExpandLabel h secret label hashedMsgs outlen
  where
    outlen = hashDigestSize h

----------------------------------------------------------------

-- | @HKDF-Expand-Label@ function.  Returns output keying material of the
-- specified length from the PRK, customized for a TLS label and context.
hkdfExpandLabel :: Hash
                -> ByteString
                -> ByteString
                -> ByteString
                -> Int
                -> ByteString
hkdfExpandLabel h secret label ctx outlen = expand' h secret hkdfLabel outlen
  where
    hkdfLabel = runPut $ do
        putWord16 $ fromIntegral outlen
        putOpaque8 ("tls13 " `BS.append` label)
        putOpaque8 ctx

expand' :: Hash -> ByteString -> ByteString -> Int -> ByteString
expand' SHA1   secret label len = expand (extractSkip secret :: PRK H.SHA1)   label len
expand' SHA256 secret label len = expand (extractSkip secret :: PRK H.SHA256) label len
expand' SHA384 secret label len = expand (extractSkip secret :: PRK H.SHA384) label len
expand' SHA512 secret label len = expand (extractSkip secret :: PRK H.SHA512) label len
expand' _ _ _ _ = error "expand'"

----------------------------------------------------------------
