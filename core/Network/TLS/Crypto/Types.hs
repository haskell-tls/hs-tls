{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE PatternSynonyms #-}

-- |
-- Module      : Network.TLS.Crypto.Types
-- License     : BSD-style
-- Maintainer  : Kazu Yamamoto <kazu@iij.ad.jp>
-- Stability   : experimental
-- Portability : unknown
module Network.TLS.Crypto.Types (
    Group (
        Group,
        P256,
        P384,
        P521,
        X25519,
        X448,
        FFDHE2048,
        FFDHE3072,
        FFDHE4096,
        FFDHE6144,
        FFDHE8192
    ),
    availableFFGroups,
    availableECGroups,
    supportedNamedGroups,
    KeyExchangeSignatureAlg (..),
) where

import Data.Word
import GHC.Generics

newtype Group = Group Word16 deriving (Eq, Generic)

{- FOURMOLU_DISABLE -}
pattern P256      :: Group
pattern P256       = Group 23
pattern P384      :: Group
pattern P384       = Group 24
pattern P521      :: Group
pattern P521       = Group 25
pattern X25519    :: Group
pattern X25519     = Group 29
pattern X448      :: Group
pattern X448       = Group 30
pattern FFDHE2048 :: Group
pattern FFDHE2048  = Group 256
pattern FFDHE3072 :: Group
pattern FFDHE3072  = Group 257
pattern FFDHE4096 :: Group
pattern FFDHE4096  = Group 258
pattern FFDHE6144 :: Group
pattern FFDHE6144  = Group 259
pattern FFDHE8192 :: Group
pattern FFDHE8192  = Group 260

instance Show Group where
    show P256      = "P256"
    show P384      = "P384"
    show P521      = "P521"
    show X25519    = "X25519"
    show X448      = "X448"
    show FFDHE2048 = "FFDHE2048"
    show FFDHE3072 = "FFDHE3072"
    show FFDHE4096 = "FFDHE4096"
    show FFDHE6144 = "FFDHE6144"
    show FFDHE8192 = "FFDHE8192"
    show (Group x) = "Group " ++ show x
{- FOURMOLU_ENABLE -}

availableFFGroups :: [Group]
availableFFGroups = [FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192]

availableECGroups :: [Group]
availableECGroups = [P256, P384, P521, X25519, X448]

supportedNamedGroups :: [Group]
supportedNamedGroups = [X25519, X448, P256, FFDHE3072, FFDHE4096, P384, FFDHE6144, FFDHE8192, P521]

-- Key-exchange signature algorithm, in close relation to ciphers
-- (before TLS 1.3).
data KeyExchangeSignatureAlg = KX_RSA | KX_DSA | KX_ECDSA
    deriving (Show, Eq)
