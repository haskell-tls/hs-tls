{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE PatternSynonyms #-}

module Network.TLS.Types.Version (
    Version (Version, SSL2, SSL3, TLS10, TLS11, TLS12, TLS13),
) where

import Codec.Serialise
import GHC.Generics

import Network.TLS.Imports

-- | Versions known to TLS
newtype Version = Version Word16 deriving (Eq, Ord, Generic)

{- FOURMOLU_DISABLE -}
pattern SSL2  :: Version
pattern SSL2   = Version 0x0200
pattern SSL3  :: Version
pattern SSL3   = Version 0x0300
pattern TLS10 :: Version
pattern TLS10  = Version 0x0301
pattern TLS11 :: Version
pattern TLS11  = Version 0x0302
pattern TLS12 :: Version
pattern TLS12  = Version 0x0303
pattern TLS13 :: Version
pattern TLS13  = Version 0x0304

instance Show Version where
    show SSL2  = "SSL2"
    show SSL3  = "SSL3"
    show TLS10 = "TLS1.0"
    show TLS11 = "TLS1.1"
    show TLS12 = "TLS1.2"
    show TLS13 = "TLS1.3"
    show (Version x) = "Version " ++ show x
{- FOURMOLU_ENABLE -}

instance Serialise Version
