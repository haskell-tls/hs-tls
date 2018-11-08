module Network.TLS.Crypto.DH
    (
    -- * DH types
      DHParams
    , DHPublic
    , DHPrivate
    , DHKey

    -- * DH methods
    , dhPublic
    , dhPrivate
    , dhParams
    , dhParamsGetP
    , dhParamsGetG
    , dhParamsGetBits
    , dhGenerateKeyPair
    , dhGetShared
    , dhValid
    , dhUnwrap
    , dhUnwrapPublic
    ) where

import qualified Crypto.PubKey.DH as DH
import           Crypto.Number.Basic (numBits)
import qualified Data.ByteArray as B
import           Network.TLS.RNG

type DHPublic   = DH.PublicNumber
type DHPrivate  = DH.PrivateNumber
type DHParams   = DH.Params
type DHKey      = DH.SharedKey

dhPublic :: Integer -> DHPublic
dhPublic = DH.PublicNumber

dhPrivate :: Integer -> DHPrivate
dhPrivate = DH.PrivateNumber

dhParams :: Integer -> Integer -> DHParams
dhParams p g = DH.Params p g (numBits p)

dhGenerateKeyPair :: MonadRandom r => DHParams -> r (DHPrivate, DHPublic)
dhGenerateKeyPair params = do
    priv <- DH.generatePrivate params
    let pub        = DH.calculatePublic params priv
    return (priv, pub)

dhGetShared :: DHParams -> DHPrivate -> DHPublic -> DHKey
dhGetShared params priv pub =
    stripLeadingZeros (DH.getShared params priv pub)
  where
    -- strips leading zeros from the result of DH.getShared, as required
    -- for DH(E) premaster secret in SSL/TLS before version 1.3.
    stripLeadingZeros (DH.SharedKey sb) = DH.SharedKey (snd $ B.span (== 0) sb)

-- Check that group element in not in the 2-element subgroup { 1, p - 1 }.
-- See RFC 7919 section 3 and NIST SP 56A rev 2 section 5.6.2.3.1.
-- This verification is enough when using a safe prime.
dhValid :: DHParams -> Integer -> Bool
dhValid (DH.Params p _ _) y = 1 < y && y < p - 1

dhUnwrap :: DHParams -> DHPublic -> [Integer]
dhUnwrap (DH.Params p g _) (DH.PublicNumber y) = [p,g,y]

dhParamsGetP :: DHParams -> Integer
dhParamsGetP (DH.Params p _ _) = p

dhParamsGetG :: DHParams -> Integer
dhParamsGetG (DH.Params _ g _) = g

dhParamsGetBits :: DHParams -> Int
dhParamsGetBits (DH.Params _ _ b) = b

dhUnwrapPublic :: DHPublic -> Integer
dhUnwrapPublic (DH.PublicNumber y) = y
