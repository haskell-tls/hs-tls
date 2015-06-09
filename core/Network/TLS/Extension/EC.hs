module Network.TLS.Extension.EC (
    CurveName(..)
  , toCurveName
  , fromCurveName
  ) where

import Crypto.PubKey.ECC.Types (CurveName(..))
import Data.Word (Word16)

toCurveName :: Word16 -> Maybe CurveName
toCurveName  1 = Just SEC_t163k1
toCurveName  2 = Just SEC_t163r1
toCurveName  3 = Just SEC_t163r2
toCurveName  4 = Just SEC_t193r1
toCurveName  5 = Just SEC_t193r2
toCurveName  6 = Just SEC_t233k1
toCurveName  7 = Just SEC_t233r1
toCurveName  8 = Just SEC_t239k1
toCurveName  9 = Just SEC_t283k1
toCurveName 10 = Just SEC_t283r1
toCurveName 11 = Just SEC_t409k1
toCurveName 12 = Just SEC_t409r1
toCurveName 13 = Just SEC_t571k1
toCurveName 14 = Just SEC_t571r1
toCurveName 15 = Just SEC_p160k1
toCurveName 16 = Just SEC_p160r1
toCurveName 17 = Just SEC_p160r2
toCurveName 18 = Just SEC_p192k1
toCurveName 19 = Just SEC_p192r1
toCurveName 20 = Just SEC_p224k1
toCurveName 21 = Just SEC_p224r1
toCurveName 22 = Just SEC_p256k1
toCurveName 23 = Just SEC_p256r1
toCurveName 24 = Just SEC_p384r1
toCurveName 25 = Just SEC_p521r1
toCurveName _  = Nothing

fromCurveName :: CurveName -> Maybe Word16
fromCurveName SEC_t163k1 = Just  1
fromCurveName SEC_t163r1 = Just  2
fromCurveName SEC_t163r2 = Just  3
fromCurveName SEC_t193r1 = Just  4
fromCurveName SEC_t193r2 = Just  5
fromCurveName SEC_t233k1 = Just  6
fromCurveName SEC_t233r1 = Just  7
fromCurveName SEC_t239k1 = Just  8
fromCurveName SEC_t283k1 = Just  9
fromCurveName SEC_t283r1 = Just 10
fromCurveName SEC_t409k1 = Just 11
fromCurveName SEC_t409r1 = Just 12
fromCurveName SEC_t571k1 = Just 13
fromCurveName SEC_t571r1 = Just 14
fromCurveName SEC_p160k1 = Just 15
fromCurveName SEC_p160r1 = Just 16
fromCurveName SEC_p160r2 = Just 17
fromCurveName SEC_p192k1 = Just 18
fromCurveName SEC_p192r1 = Just 19
fromCurveName SEC_p224k1 = Just 20
fromCurveName SEC_p224r1 = Just 21
fromCurveName SEC_p256k1 = Just 22
fromCurveName SEC_p256r1 = Just 23
fromCurveName SEC_p384r1 = Just 24
fromCurveName SEC_p521r1 = Just 25
fromCurveName _          = Nothing
