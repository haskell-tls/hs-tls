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
        FFDHE8192,
        MLKEM512,
        MLKEM768,
        MLKEM1024,
        X25519MLKEM768,
        P256MLKEM768,
        P384MLKEM1024
    ),
    availableFFGroups,
    availableECGroups,
    availableHybridGroups,
    supportedNamedGroups,
    KeyExchangeSignatureAlg (..),
) where

import Codec.Serialise
import Data.Word
import GHC.Generics

newtype Group = Group Word16 deriving (Eq, Generic)
instance Serialise Group

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
pattern MLKEM512  :: Group
pattern MLKEM512   = Group 512
pattern MLKEM768  :: Group
pattern MLKEM768   = Group 513
pattern MLKEM1024 :: Group
pattern MLKEM1024  = Group 514
pattern X25519MLKEM768 :: Group
pattern X25519MLKEM768  = Group 4588
pattern P256MLKEM768   :: Group
pattern P256MLKEM768    = Group 4587
pattern P384MLKEM1024  :: Group
pattern P384MLKEM1024   = Group 4589

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
    show MLKEM512  = "MLKEM512"
    show MLKEM768  = "MLKEM768"
    show MLKEM1024 = "MLKEM1024"
    show X25519MLKEM768 = "X25519MLKEM768"
    show P256MLKEM768   = "P256MLKEM768"
    show P384MLKEM1024  = "P384MLKEM1024"
    show (Group x) = "Group " ++ show x
{- FOURMOLU_ENABLE -}

availableFFGroups :: [Group]
availableFFGroups = [FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192]

availableECGroups :: [Group]
availableECGroups = [P256, P384, P521, X25519, X448]

availableHybridGroups :: [Group]
availableHybridGroups = [X25519MLKEM768, P256MLKEM768, P384MLKEM1024]

-- | A list for named groups.  The ordering is for client preference
--   because server preference is not used in our server
--   implementation.
supportedNamedGroups :: [Group]
supportedNamedGroups =
    [ X25519 -- 128 bits security
    , P256 -- 128 bits security
    , P384 -- 192 bits security
    , X448 -- 224 bits security
    , P521 -- 256 bits security
    --    , FFDHE2048 -- 103 bits security
    , FFDHE3072 -- 125 bits security
    , FFDHE4096 -- 150 bits security
    , FFDHE6144 -- 175 bits security
    , FFDHE8192 -- 192 bits security
    , X25519MLKEM768
    , P256MLKEM768
    , P384MLKEM1024
    -- Don't include sole MLKEM intentionally.
    ]

-- Key-exchange signature algorithm, in close relation to ciphers
-- (before TLS 1.3).
data KeyExchangeSignatureAlg = KX_RSA | KX_DSA | KX_ECDSA
    deriving (Show, Eq)
