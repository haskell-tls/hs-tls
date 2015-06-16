{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Network.TLS.RNG
    ( StateRNG(..)
    , withTLSRNG
    , newStateRNG
    , MonadRandom
    , getRandomBytes
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

newStateRNG :: MonadRandom randomly => randomly StateRNG
newStateRNG = StateRNG `fmap` drgNew
