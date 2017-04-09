-- |
-- Module      : Network.TLS.Extension.Group
-- License     : BSD-style
-- Maintainer  : Kazu Yamamoto <kazu@iij.ad.jp>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Extension.Group where

import Data.Word (Word16)

data Group = P256 | P384 | P521 | X25519 | X448
           | FFDHE2048 | FFDHE3072 | FFDHE4096 | FFDHE6144 | FFDHE8192
           deriving (Eq, Show)

-- EnumSafe16 cannot be used due to recycling imports.
fromGroup :: Group -> Word16
fromGroup P256      =  23
fromGroup P384      =  24
fromGroup P521      =  25
fromGroup X25519    =  29
fromGroup X448      =  30
fromGroup FFDHE2048 = 256
fromGroup FFDHE3072 = 257
fromGroup FFDHE4096 = 258
fromGroup FFDHE6144 = 259
fromGroup FFDHE8192 = 260

toGroup :: Word16 -> Maybe Group
toGroup  23 = Just P256
toGroup  24 = Just P384
toGroup  25 = Just P521
toGroup  29 = Just X25519
toGroup  30 = Just X448
toGroup 256 = Just FFDHE2048
toGroup 257 = Just FFDHE3072
toGroup 258 = Just FFDHE4096
toGroup 259 = Just FFDHE6144
toGroup 260 = Just FFDHE8192
toGroup _   = Nothing

availableGroups :: [Group]
availableGroups = [P256,P384,P521,X25519,X448]
