-- |
-- Module      : Network.TLS.Crypto.IES
-- License     : BSD-style
-- Maintainer  : Kazu Yamamoto <kazu@iij.ad.jp>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Crypto.IES
    (
      GroupPublic
    , GroupPrivate
    , GroupKey
    -- * Group methods
    , groupGenerateKeyPair
    , groupGetPubShared
    , groupGetShared
    , encodeGroupPublic
    , decodeGroupPublic
    ) where

import Control.Arrow
import Crypto.ECC
import Crypto.Error
import Crypto.PubKey.DH
import Crypto.PubKey.ECIES
import Data.Proxy
import Network.TLS.Crypto.Types
import Network.TLS.Extra.FFDHE
import Network.TLS.Imports
import Network.TLS.RNG
import Network.TLS.Util.Serialization (os2ip,i2ospOf_)

data GroupPrivate = GroupPri_P256 (Scalar Curve_P256R1)
                  | GroupPri_P384 (Scalar Curve_P384R1)
                  | GroupPri_P521 (Scalar Curve_P521R1)
                  | GroupPri_X255 (Scalar Curve_X25519)
                  | GroupPri_X448 (Scalar Curve_X448)
                  | GroupPri_FFDHE2048 PrivateNumber
                  | GroupPri_FFDHE3072 PrivateNumber
                  | GroupPri_FFDHE4096 PrivateNumber
                  | GroupPri_FFDHE6144 PrivateNumber
                  | GroupPri_FFDHE8192 PrivateNumber
                  deriving (Eq, Show)

data GroupPublic = GroupPub_P256 (Point Curve_P256R1)
                 | GroupPub_P384 (Point Curve_P384R1)
                 | GroupPub_P521 (Point Curve_P521R1)
                 | GroupPub_X255 (Point Curve_X25519)
                 | GroupPub_X448 (Point Curve_X448)
                 | GroupPub_FFDHE2048 PublicNumber
                 | GroupPub_FFDHE3072 PublicNumber
                 | GroupPub_FFDHE4096 PublicNumber
                 | GroupPub_FFDHE6144 PublicNumber
                 | GroupPub_FFDHE8192 PublicNumber
                 deriving (Eq, Show)

type GroupKey = SharedSecret

p256 :: Proxy Curve_P256R1
p256 = Proxy

p384 :: Proxy Curve_P384R1
p384 = Proxy

p521 :: Proxy Curve_P521R1
p521 = Proxy

x25519 :: Proxy Curve_X25519
x25519 = Proxy

x448 :: Proxy Curve_X448
x448 = Proxy

groupGenerateKeyPair :: MonadRandom r => Group -> r (GroupPrivate, GroupPublic)
groupGenerateKeyPair P256   =
    (GroupPri_P256,GroupPub_P256) `fs` curveGenerateKeyPair p256
groupGenerateKeyPair P384   =
    (GroupPri_P384,GroupPub_P384) `fs` curveGenerateKeyPair p384
groupGenerateKeyPair P521   =
    (GroupPri_P521,GroupPub_P521) `fs` curveGenerateKeyPair p521
groupGenerateKeyPair X25519 =
    (GroupPri_X255,GroupPub_X255) `fs` curveGenerateKeyPair x25519
groupGenerateKeyPair X448 =
    (GroupPri_X448,GroupPub_X448) `fs` curveGenerateKeyPair x448
groupGenerateKeyPair FFDHE2048 = gen ffdhe2048 GroupPri_FFDHE2048 GroupPub_FFDHE2048
groupGenerateKeyPair FFDHE3072 = gen ffdhe3072 GroupPri_FFDHE3072 GroupPub_FFDHE3072
groupGenerateKeyPair FFDHE4096 = gen ffdhe4096 GroupPri_FFDHE4096 GroupPub_FFDHE4096
groupGenerateKeyPair FFDHE6144 = gen ffdhe6144 GroupPri_FFDHE6144 GroupPub_FFDHE6144
groupGenerateKeyPair FFDHE8192 = gen ffdhe8192 GroupPri_FFDHE8192 GroupPub_FFDHE8192

fs :: MonadRandom r
   => (Scalar a -> GroupPrivate, Point a -> GroupPublic)
   -> r (KeyPair a)
   -> r (GroupPrivate, GroupPublic)
(t1, t2) `fs` action = do
    keypair <- action
    let pub = keypairGetPublic keypair
        pri = keypairGetPrivate keypair
    return (t1 pri, t2 pub)

gen :: MonadRandom r
    => Params
    -> (PrivateNumber -> GroupPrivate)
    -> (PublicNumber -> GroupPublic)
    -> r (GroupPrivate, GroupPublic)
gen params priTag pubTag = do
    pri <- generatePrivate params
    let pub = calculatePublic params pri
    return (priTag pri, pubTag pub)

groupGetPubShared :: MonadRandom r => GroupPublic -> r (GroupPublic, GroupKey)
groupGetPubShared (GroupPub_P256 pub) =
    first GroupPub_P256 <$> deriveEncrypt p256 pub
groupGetPubShared (GroupPub_P384 pub) =
    first GroupPub_P384 <$> deriveEncrypt p384 pub
groupGetPubShared (GroupPub_P521 pub) =
    first GroupPub_P521 <$> deriveEncrypt p521 pub
groupGetPubShared (GroupPub_X255 pub) =
    first GroupPub_X255 <$> deriveEncrypt x25519 pub
groupGetPubShared (GroupPub_X448 pub) =
    first GroupPub_X448 <$> deriveEncrypt x448 pub
groupGetPubShared (GroupPub_FFDHE2048 pub) = getPubShared ffdhe2048 pub GroupPub_FFDHE2048
groupGetPubShared (GroupPub_FFDHE3072 pub) = getPubShared ffdhe3072 pub GroupPub_FFDHE3072
groupGetPubShared (GroupPub_FFDHE4096 pub) = getPubShared ffdhe4096 pub GroupPub_FFDHE4096
groupGetPubShared (GroupPub_FFDHE6144 pub) = getPubShared ffdhe6144 pub GroupPub_FFDHE6144
groupGetPubShared (GroupPub_FFDHE8192 pub) = getPubShared ffdhe8192 pub GroupPub_FFDHE8192

getPubShared :: MonadRandom r
             => Params
             -> PublicNumber
             -> (PublicNumber -> GroupPublic)
             -> r (GroupPublic, GroupKey)
getPubShared params pub pubTag = do
    mypri <- generatePrivate params
    let mypub = calculatePublic params mypri
    let SharedKey share = getShared params mypri pub
    return (pubTag mypub, SharedSecret share)

groupGetShared ::  GroupPublic -> GroupPrivate -> Maybe GroupKey
groupGetShared (GroupPub_P256 pub) (GroupPri_P256 pri) = Just $ deriveDecrypt p256 pub pri
groupGetShared (GroupPub_P384 pub) (GroupPri_P384 pri) = Just $ deriveDecrypt p384 pub pri
groupGetShared (GroupPub_P521 pub) (GroupPri_P521 pri) = Just $ deriveDecrypt p521 pub pri
groupGetShared (GroupPub_X255 pub) (GroupPri_X255 pri) = Just $ deriveDecrypt x25519 pub pri
groupGetShared (GroupPub_X448 pub) (GroupPri_X448 pri) = Just $ deriveDecrypt x448 pub pri
groupGetShared (GroupPub_FFDHE2048 pub) (GroupPri_FFDHE2048 pri) = Just $ calcShared ffdhe2048 pub pri
groupGetShared (GroupPub_FFDHE3072 pub) (GroupPri_FFDHE3072 pri) = Just $ calcShared ffdhe3072 pub pri
groupGetShared (GroupPub_FFDHE4096 pub) (GroupPri_FFDHE4096 pri) = Just $ calcShared ffdhe4096 pub pri
groupGetShared (GroupPub_FFDHE6144 pub) (GroupPri_FFDHE6144 pri) = Just $ calcShared ffdhe6144 pub pri
groupGetShared (GroupPub_FFDHE8192 pub) (GroupPri_FFDHE8192 pri) = Just $ calcShared ffdhe8192 pub pri
groupGetShared _ _ = Nothing

calcShared :: Params -> PublicNumber -> PrivateNumber -> SharedSecret
calcShared params pub pri = SharedSecret share
  where
    SharedKey share = getShared params pri pub

encodeGroupPublic :: GroupPublic -> Bytes
encodeGroupPublic (GroupPub_P256 p) = encodePoint p256 p
encodeGroupPublic (GroupPub_P384 p) = encodePoint p384 p
encodeGroupPublic (GroupPub_P521 p) = encodePoint p521 p
encodeGroupPublic (GroupPub_X255 p) = encodePoint x25519 p
encodeGroupPublic (GroupPub_X448 p) = encodePoint x448 p
encodeGroupPublic (GroupPub_FFDHE2048 p) = enc ffdhe2048 p
encodeGroupPublic (GroupPub_FFDHE3072 p) = enc ffdhe3072 p
encodeGroupPublic (GroupPub_FFDHE4096 p) = enc ffdhe4096 p
encodeGroupPublic (GroupPub_FFDHE6144 p) = enc ffdhe6144 p
encodeGroupPublic (GroupPub_FFDHE8192 p) = enc ffdhe8192 p

enc :: Params -> PublicNumber -> Bytes
enc params (PublicNumber p) = i2ospOf_ ((params_bits params + 7) `div` 8) p

decodeGroupPublic :: Group -> Bytes -> Either CryptoError GroupPublic
decodeGroupPublic P256   bs = eitherCryptoError $ GroupPub_P256 <$> decodePoint p256 bs
decodeGroupPublic P384   bs = eitherCryptoError $ GroupPub_P384 <$> decodePoint p384 bs
decodeGroupPublic P521   bs = eitherCryptoError $ GroupPub_P521 <$> decodePoint p521 bs
decodeGroupPublic X25519 bs = eitherCryptoError $ GroupPub_X255 <$> decodePoint x25519 bs
decodeGroupPublic X448 bs = eitherCryptoError $ GroupPub_X448 <$> decodePoint x448 bs
decodeGroupPublic FFDHE2048 bs = Right . GroupPub_FFDHE2048 . PublicNumber $ os2ip bs
decodeGroupPublic FFDHE3072 bs = Right . GroupPub_FFDHE3072 . PublicNumber $ os2ip bs
decodeGroupPublic FFDHE4096 bs = Right . GroupPub_FFDHE4096 . PublicNumber $ os2ip bs
decodeGroupPublic FFDHE6144 bs = Right . GroupPub_FFDHE6144 . PublicNumber $ os2ip bs
decodeGroupPublic FFDHE8192 bs = Right . GroupPub_FFDHE8192 . PublicNumber $ os2ip bs
