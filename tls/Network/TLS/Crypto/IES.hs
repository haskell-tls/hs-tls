-- | (Elliptic Curve) Integrated Encryption Scheme
--   KEM(Key Encapsulation Mechanism) based APIs
--
-- Module      : Network.TLS.Crypto.IES
-- License     : BSD-style
-- Maintainer  : Kazu Yamamoto <kazu@iij.ad.jp>
-- Stability   : experimental
-- Portability : unknown
module Network.TLS.Crypto.IES (
    GroupPublic,
    GroupPrivate,
    GroupKey,

    -- * Group methods
    groupGenerateKeyPair,
    groupEncapsulate,
    groupDecapsulate,
    groupEncodePublic,
    groupDecodePublic,

    -- * Compatibility with 'Network.TLS.Crypto.DH'
    dhParamsForGroup,
    dhGroupGenerateKeyPair,
    dhGroupGetPubShared,
) where

import Control.Arrow
import Crypto.ECC
import Crypto.Error
import Crypto.Number.Generate
import Crypto.PubKey.DH (PrivateNumber (..), PublicNumber (..))
import qualified Crypto.PubKey.DH as DH
import Crypto.PubKey.ECIES
import qualified Data.ByteArray as B
import Data.Proxy

import Network.TLS.Crypto.Types
import Network.TLS.Extra.FFDHE
import Network.TLS.Imports
import Network.TLS.RNG
import Network.TLS.Util.Serialization (i2ospOf_, os2ip)

data GroupPrivate
    = GroupPri_P256 (Scalar Curve_P256R1)
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

data GroupPublic
    = GroupPub_P256 (Point Curve_P256R1)
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

dhParamsForGroup :: Group -> Maybe DH.Params
dhParamsForGroup FFDHE2048 = Just ffdhe2048
dhParamsForGroup FFDHE3072 = Just ffdhe3072
dhParamsForGroup FFDHE4096 = Just ffdhe4096
dhParamsForGroup FFDHE6144 = Just ffdhe6144
dhParamsForGroup FFDHE8192 = Just ffdhe8192
dhParamsForGroup _ = Nothing

groupGenerateKeyPair :: MonadRandom r => Group -> r (GroupPrivate, GroupPublic)
groupGenerateKeyPair P256 =
    (GroupPri_P256, GroupPub_P256) `fs` curveGenerateKeyPair p256
groupGenerateKeyPair P384 =
    (GroupPri_P384, GroupPub_P384) `fs` curveGenerateKeyPair p384
groupGenerateKeyPair P521 =
    (GroupPri_P521, GroupPub_P521) `fs` curveGenerateKeyPair p521
groupGenerateKeyPair X25519 =
    (GroupPri_X255, GroupPub_X255) `fs` curveGenerateKeyPair x25519
groupGenerateKeyPair X448 =
    (GroupPri_X448, GroupPub_X448) `fs` curveGenerateKeyPair x448
groupGenerateKeyPair FFDHE2048 = gen ffdhe2048 exp2048 GroupPri_FFDHE2048 GroupPub_FFDHE2048
groupGenerateKeyPair FFDHE3072 = gen ffdhe3072 exp3072 GroupPri_FFDHE3072 GroupPub_FFDHE3072
groupGenerateKeyPair FFDHE4096 = gen ffdhe4096 exp4096 GroupPri_FFDHE4096 GroupPub_FFDHE4096
groupGenerateKeyPair FFDHE6144 = gen ffdhe6144 exp6144 GroupPri_FFDHE6144 GroupPub_FFDHE6144
groupGenerateKeyPair FFDHE8192 = gen ffdhe8192 exp8192 GroupPri_FFDHE8192 GroupPub_FFDHE8192
groupGenerateKeyPair _ = error "groupGenerateKeyPair"

dhGroupGenerateKeyPair
    :: MonadRandom r => Group -> r (DH.Params, PrivateNumber, PublicNumber)
dhGroupGenerateKeyPair FFDHE2048 = addParams ffdhe2048 (gen' ffdhe2048 exp2048)
dhGroupGenerateKeyPair FFDHE3072 = addParams ffdhe3072 (gen' ffdhe3072 exp3072)
dhGroupGenerateKeyPair FFDHE4096 = addParams ffdhe4096 (gen' ffdhe4096 exp4096)
dhGroupGenerateKeyPair FFDHE6144 = addParams ffdhe6144 (gen' ffdhe6144 exp6144)
dhGroupGenerateKeyPair FFDHE8192 = addParams ffdhe8192 (gen' ffdhe8192 exp8192)
dhGroupGenerateKeyPair grp = error ("invalid FFDHE group: " ++ show grp)

addParams :: Functor f => DH.Params -> f (a, b) -> f (DH.Params, a, b)
addParams params = fmap $ \(a, b) -> (params, a, b)

fs
    :: MonadRandom r
    => (Scalar a -> GroupPrivate, Point a -> GroupPublic)
    -> r (KeyPair a)
    -> r (GroupPrivate, GroupPublic)
(t1, t2) `fs` action = do
    keypair <- action
    let pub = keypairGetPublic keypair
        pri = keypairGetPrivate keypair
    return (t1 pri, t2 pub)

gen
    :: MonadRandom r
    => DH.Params
    -> Int
    -> (PrivateNumber -> GroupPrivate)
    -> (PublicNumber -> GroupPublic)
    -> r (GroupPrivate, GroupPublic)
gen params expBits priTag pubTag = (priTag *** pubTag) <$> gen' params expBits

gen'
    :: MonadRandom r
    => DH.Params
    -> Int
    -> r (PrivateNumber, PublicNumber)
gen' params expBits = (id &&& DH.calculatePublic params) <$> generatePriv expBits

groupEncapsulate
    :: MonadRandom r => GroupPublic -> r (Maybe (GroupPublic, GroupKey))
groupEncapsulate (GroupPub_P256 pub) =
    fmap (first GroupPub_P256) . maybeCryptoError <$> deriveEncrypt p256 pub
groupEncapsulate (GroupPub_P384 pub) =
    fmap (first GroupPub_P384) . maybeCryptoError <$> deriveEncrypt p384 pub
groupEncapsulate (GroupPub_P521 pub) =
    fmap (first GroupPub_P521) . maybeCryptoError <$> deriveEncrypt p521 pub
groupEncapsulate (GroupPub_X255 pub) =
    fmap (first GroupPub_X255) . maybeCryptoError <$> deriveEncrypt x25519 pub
groupEncapsulate (GroupPub_X448 pub) =
    fmap (first GroupPub_X448) . maybeCryptoError <$> deriveEncrypt x448 pub
groupEncapsulate (GroupPub_FFDHE2048 pub) = getDHPubShared ffdhe2048 exp2048 pub GroupPub_FFDHE2048
groupEncapsulate (GroupPub_FFDHE3072 pub) = getDHPubShared ffdhe3072 exp3072 pub GroupPub_FFDHE3072
groupEncapsulate (GroupPub_FFDHE4096 pub) = getDHPubShared ffdhe4096 exp4096 pub GroupPub_FFDHE4096
groupEncapsulate (GroupPub_FFDHE6144 pub) = getDHPubShared ffdhe6144 exp6144 pub GroupPub_FFDHE6144
groupEncapsulate (GroupPub_FFDHE8192 pub) = getDHPubShared ffdhe8192 exp8192 pub GroupPub_FFDHE8192

dhGroupGetPubShared
    :: MonadRandom r => Group -> PublicNumber -> r (Maybe (PublicNumber, DH.SharedKey))
dhGroupGetPubShared FFDHE2048 pub = getDHPubShared' ffdhe2048 exp2048 pub
dhGroupGetPubShared FFDHE3072 pub = getDHPubShared' ffdhe3072 exp3072 pub
dhGroupGetPubShared FFDHE4096 pub = getDHPubShared' ffdhe4096 exp4096 pub
dhGroupGetPubShared FFDHE6144 pub = getDHPubShared' ffdhe6144 exp6144 pub
dhGroupGetPubShared FFDHE8192 pub = getDHPubShared' ffdhe8192 exp8192 pub
dhGroupGetPubShared _ _ = return Nothing

getDHPubShared
    :: MonadRandom r
    => DH.Params
    -> Int
    -> PublicNumber
    -> (PublicNumber -> GroupPublic)
    -> r (Maybe (GroupPublic, GroupKey))
getDHPubShared params expBits pub pubTag
    | not (valid params pub) = return Nothing
    | otherwise = do
        mypri <- generatePriv expBits
        let mypub = DH.calculatePublic params mypri
        let DH.SharedKey share = DH.getShared params mypri pub
        return $ Just (pubTag mypub, SharedSecret share)

getDHPubShared'
    :: MonadRandom r
    => DH.Params
    -> Int
    -> PublicNumber
    -> r (Maybe (PublicNumber, DH.SharedKey))
getDHPubShared' params expBits pub
    | not (valid params pub) = return Nothing
    | otherwise = do
        mypri <- generatePriv expBits
        let share = stripLeadingZeros (DH.getShared params mypri pub)
        return $ Just (DH.calculatePublic params mypri, DH.SharedKey share)

groupDecapsulate :: GroupPublic -> GroupPrivate -> Maybe GroupKey
groupDecapsulate (GroupPub_P256 pub) (GroupPri_P256 pri) = maybeCryptoError $ deriveDecrypt p256 pub pri
groupDecapsulate (GroupPub_P384 pub) (GroupPri_P384 pri) = maybeCryptoError $ deriveDecrypt p384 pub pri
groupDecapsulate (GroupPub_P521 pub) (GroupPri_P521 pri) = maybeCryptoError $ deriveDecrypt p521 pub pri
groupDecapsulate (GroupPub_X255 pub) (GroupPri_X255 pri) = maybeCryptoError $ deriveDecrypt x25519 pub pri
groupDecapsulate (GroupPub_X448 pub) (GroupPri_X448 pri) = maybeCryptoError $ deriveDecrypt x448 pub pri
groupDecapsulate (GroupPub_FFDHE2048 pub) (GroupPri_FFDHE2048 pri) = calcDHShared ffdhe2048 pub pri
groupDecapsulate (GroupPub_FFDHE3072 pub) (GroupPri_FFDHE3072 pri) = calcDHShared ffdhe3072 pub pri
groupDecapsulate (GroupPub_FFDHE4096 pub) (GroupPri_FFDHE4096 pri) = calcDHShared ffdhe4096 pub pri
groupDecapsulate (GroupPub_FFDHE6144 pub) (GroupPri_FFDHE6144 pri) = calcDHShared ffdhe6144 pub pri
groupDecapsulate (GroupPub_FFDHE8192 pub) (GroupPri_FFDHE8192 pri) = calcDHShared ffdhe8192 pub pri
groupDecapsulate _ _ = Nothing

calcDHShared :: DH.Params -> PublicNumber -> PrivateNumber -> Maybe SharedSecret
calcDHShared params pub pri
    | valid params pub = Just $ SharedSecret share
    | otherwise = Nothing
  where
    DH.SharedKey share = DH.getShared params pri pub

groupEncodePublic :: GroupPublic -> ByteString
groupEncodePublic (GroupPub_P256 p) = encodePoint p256 p
groupEncodePublic (GroupPub_P384 p) = encodePoint p384 p
groupEncodePublic (GroupPub_P521 p) = encodePoint p521 p
groupEncodePublic (GroupPub_X255 p) = encodePoint x25519 p
groupEncodePublic (GroupPub_X448 p) = encodePoint x448 p
groupEncodePublic (GroupPub_FFDHE2048 p) = enc ffdhe2048 p
groupEncodePublic (GroupPub_FFDHE3072 p) = enc ffdhe3072 p
groupEncodePublic (GroupPub_FFDHE4096 p) = enc ffdhe4096 p
groupEncodePublic (GroupPub_FFDHE6144 p) = enc ffdhe6144 p
groupEncodePublic (GroupPub_FFDHE8192 p) = enc ffdhe8192 p

enc :: DH.Params -> PublicNumber -> ByteString
enc params (PublicNumber p) = i2ospOf_ ((DH.params_bits params + 7) `div` 8) p

groupDecodePublic :: Group -> ByteString -> Either CryptoError GroupPublic
groupDecodePublic P256 bs = eitherCryptoError $ GroupPub_P256 <$> decodePoint p256 bs
groupDecodePublic P384 bs = eitherCryptoError $ GroupPub_P384 <$> decodePoint p384 bs
groupDecodePublic P521 bs = eitherCryptoError $ GroupPub_P521 <$> decodePoint p521 bs
groupDecodePublic X25519 bs = eitherCryptoError $ GroupPub_X255 <$> decodePoint x25519 bs
groupDecodePublic X448 bs = eitherCryptoError $ GroupPub_X448 <$> decodePoint x448 bs
groupDecodePublic FFDHE2048 bs = Right . GroupPub_FFDHE2048 . PublicNumber $ os2ip bs
groupDecodePublic FFDHE3072 bs = Right . GroupPub_FFDHE3072 . PublicNumber $ os2ip bs
groupDecodePublic FFDHE4096 bs = Right . GroupPub_FFDHE4096 . PublicNumber $ os2ip bs
groupDecodePublic FFDHE6144 bs = Right . GroupPub_FFDHE6144 . PublicNumber $ os2ip bs
groupDecodePublic FFDHE8192 bs = Right . GroupPub_FFDHE8192 . PublicNumber $ os2ip bs
groupDecodePublic _ _ = error "groupDecodePublic"

-- Check that group element in not in the 2-element subgroup { 1, p - 1 }.
-- See RFC 7919 section 3 and NIST SP 56A rev 2 section 5.6.2.3.1.
valid :: DH.Params -> PublicNumber -> Bool
valid (DH.Params p _ _) (PublicNumber y) = 1 < y && y < p - 1

-- strips leading zeros from the result of getShared, as required
-- for DH(E) pre-main secret in SSL/TLS before version 1.3.
stripLeadingZeros :: DH.SharedKey -> B.ScrubbedBytes
stripLeadingZeros (DH.SharedKey sb) = snd $ B.span (== 0) sb

-- Use short exponents as optimization, see RFC 7919 section 5.2.
generatePriv :: MonadRandom r => Int -> r PrivateNumber
generatePriv e = PrivateNumber <$> generateParams e (Just SetHighest) False

-- Short exponent bit sizes from RFC 7919 appendix A, rounded to next
-- multiple of 16 bits, i.e. going through a function like:
-- let shortExp n = head [ e | i <- [1..], let e = n + i, e `mod` 16 == 0 ]
exp2048 :: Int
exp3072 :: Int
exp4096 :: Int
exp6144 :: Int
exp8192 :: Int
exp2048 = 240 -- shortExp 225
exp3072 = 288 -- shortExp 275
exp4096 = 336 -- shortExp 325
exp6144 = 384 -- shortExp 375
exp8192 = 416 -- shortExp 400
