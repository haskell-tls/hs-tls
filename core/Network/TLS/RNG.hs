{-# LANGUAGE ExistentialQuantification, RankNTypes #-}
module Network.TLS.RNG
    ( StateRNG(..)
    , withTLSRNG
    ) where

import Crypto.Random.API

data StateRNG = forall g . CPRG g => StateRNG g

instance Show StateRNG where
    show _ = "rng[..]"

withTLSRNG :: StateRNG -> (forall g . CPRG g => g -> (a,g)) -> (a, StateRNG)
withTLSRNG (StateRNG rng) f = let (a, rng') = f rng
                               in (a, StateRNG rng')

