{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Network.TLS.RNG
    ( StateRNG(..)
    , withTLSRNG
    , MonadRandom
    ) where

import Crypto.Random

newtype StateRNG = StateRNG ChaChaDRG
    deriving (DRG)

instance Show StateRNG where
    show _ = "rng[..]"

withTLSRNG :: StateRNG
           -> MonadPseudoRandom StateRNG a
           -> (a, StateRNG)
withTLSRNG rng f = withDRG rng f
