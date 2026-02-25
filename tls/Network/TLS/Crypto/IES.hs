-- | (Elliptic Curve) Integrated Encryption Scheme
--   KEM(Key Encapsulation Mechanism) based APIs
--
-- Module      : Network.TLS.Crypto.IES
-- License     : BSD-style
-- Maintainer  : Kazu Yamamoto <kazu@iij.ad.jp>
-- Stability   : experimental
-- Portability : unknown
module Network.TLS.Crypto.IES (
    GroupPublicA,
    GroupPublicB,
    GroupPrivate,
    GroupKey,

    -- * Group methods
    groupGenerateKeyPair,
    groupEncapsulate,
    groupDecapsulate,
    groupEncodePublicA,
    groupDecodePublicA,
    groupEncodePublicB,
    groupDecodePublicB,

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
import Crypto.PubKey.ML_KEM (ML_KEM_1024, ML_KEM_512, ML_KEM_768)
import qualified Crypto.PubKey.ML_KEM as ML
import qualified Data.ByteArray as B
import qualified Data.ByteArray as BS
import Data.Proxy

import Network.TLS.Crypto.Types
import Network.TLS.Extra.FFDHE
import Network.TLS.Imports
import Network.TLS.RNG
import Network.TLS.Util.Serialization (i2ospOf_, os2ip)

{- FOURMOLU_DISABLE -}
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
    | GroupPri_MLKEM512       (ML.DecapsulationKey ML_KEM_512)
    | GroupPri_MLKEM768       (ML.DecapsulationKey ML_KEM_768)
    | GroupPri_MLKEM1024      (ML.DecapsulationKey ML_KEM_1024)
    | GroupPri_X25519MLKEM768 (Scalar Curve_X25519, ML.DecapsulationKey ML_KEM_768)
    | GroupPri_P256MLKEM768   (Scalar Curve_P256R1, ML.DecapsulationKey ML_KEM_768)
    | GroupPri_P384MLKEM1024  (Scalar Curve_P384R1, ML.DecapsulationKey ML_KEM_1024)
    deriving (Eq, Show)
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
data GroupPublicA
    = GroupPubA_P256 (Point Curve_P256R1)
    | GroupPubA_P384 (Point Curve_P384R1)
    | GroupPubA_P521 (Point Curve_P521R1)
    | GroupPubA_X255 (Point Curve_X25519)
    | GroupPubA_X448 (Point Curve_X448)
    | GroupPubA_FFDHE2048 PublicNumber
    | GroupPubA_FFDHE3072 PublicNumber
    | GroupPubA_FFDHE4096 PublicNumber
    | GroupPubA_FFDHE6144 PublicNumber
    | GroupPubA_FFDHE8192 PublicNumber
    | GroupPubA_MLKEM512       (ML.EncapsulationKey ML_KEM_512)
    | GroupPubA_MLKEM768       (ML.EncapsulationKey ML_KEM_768)
    | GroupPubA_MLKEM1024      (ML.EncapsulationKey ML_KEM_1024)
    | GroupPubA_X25519MLKEM768 (Point Curve_X25519, ML.EncapsulationKey ML_KEM_768)
    | GroupPubA_P256MLKEM768   (Point Curve_P256R1, ML.EncapsulationKey ML_KEM_768)
    | GroupPubA_P384MLKEM1024  (Point Curve_P384R1, ML.EncapsulationKey ML_KEM_1024)
    deriving (Eq, Show)
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
data GroupPublicB
    = GroupPubB_P256 (Point Curve_P256R1)
    | GroupPubB_P384 (Point Curve_P384R1)
    | GroupPubB_P521 (Point Curve_P521R1)
    | GroupPubB_X255 (Point Curve_X25519)
    | GroupPubB_X448 (Point Curve_X448)
    | GroupPubB_FFDHE2048 PublicNumber
    | GroupPubB_FFDHE3072 PublicNumber
    | GroupPubB_FFDHE4096 PublicNumber
    | GroupPubB_FFDHE6144 PublicNumber
    | GroupPubB_FFDHE8192 PublicNumber
    | GroupPubB_MLKEM512       (ML.Ciphertext ML_KEM_512)
    | GroupPubB_MLKEM768       (ML.Ciphertext ML_KEM_768)
    | GroupPubB_MLKEM1024      (ML.Ciphertext ML_KEM_1024)
    | GroupPubB_X25519MLKEM768 (Point Curve_X25519, ML.Ciphertext ML_KEM_768)
    | GroupPubB_P256MLKEM768   (Point Curve_P256R1, ML.Ciphertext ML_KEM_768)
    | GroupPubB_P384MLKEM1024  (Point Curve_P384R1, ML.Ciphertext ML_KEM_1024)
    deriving (Eq, Show)
{- FOURMOLU_ENABLE -}

type GroupKey = ByteString

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

mlkem512 :: Proxy ML_KEM_512
mlkem512 = Proxy

mlkem768 :: Proxy ML_KEM_768
mlkem768 = Proxy

mlkem1024 :: Proxy ML_KEM_1024
mlkem1024 = Proxy

dhParamsForGroup :: Group -> Maybe DH.Params
dhParamsForGroup FFDHE2048 = Just ffdhe2048
dhParamsForGroup FFDHE3072 = Just ffdhe3072
dhParamsForGroup FFDHE4096 = Just ffdhe4096
dhParamsForGroup FFDHE6144 = Just ffdhe6144
dhParamsForGroup FFDHE8192 = Just ffdhe8192
dhParamsForGroup _ = Nothing

groupGenerateKeyPair :: MonadRandom r => Group -> r (GroupPrivate, GroupPublicA)
groupGenerateKeyPair P256 =
    (GroupPri_P256, GroupPubA_P256) `fs` curveGenerateKeyPair p256
groupGenerateKeyPair P384 =
    (GroupPri_P384, GroupPubA_P384) `fs` curveGenerateKeyPair p384
groupGenerateKeyPair P521 =
    (GroupPri_P521, GroupPubA_P521) `fs` curveGenerateKeyPair p521
groupGenerateKeyPair X25519 =
    (GroupPri_X255, GroupPubA_X255) `fs` curveGenerateKeyPair x25519
groupGenerateKeyPair X448 =
    (GroupPri_X448, GroupPubA_X448) `fs` curveGenerateKeyPair x448
groupGenerateKeyPair FFDHE2048 = gen ffdhe2048 exp2048 GroupPri_FFDHE2048 GroupPubA_FFDHE2048
groupGenerateKeyPair FFDHE3072 = gen ffdhe3072 exp3072 GroupPri_FFDHE3072 GroupPubA_FFDHE3072
groupGenerateKeyPair FFDHE4096 = gen ffdhe4096 exp4096 GroupPri_FFDHE4096 GroupPubA_FFDHE4096
groupGenerateKeyPair FFDHE6144 = gen ffdhe6144 exp6144 GroupPri_FFDHE6144 GroupPubA_FFDHE6144
groupGenerateKeyPair FFDHE8192 = gen ffdhe8192 exp8192 GroupPri_FFDHE8192 GroupPubA_FFDHE8192
groupGenerateKeyPair MLKEM512 = do
    (e, d) <- ML.generate mlkem512
    return (GroupPri_MLKEM512 d, GroupPubA_MLKEM512 e)
groupGenerateKeyPair MLKEM768 = do
    (e, d) <- ML.generate mlkem768
    return (GroupPri_MLKEM768 d, GroupPubA_MLKEM768 e)
groupGenerateKeyPair MLKEM1024 = do
    (e, d) <- ML.generate mlkem1024
    return (GroupPri_MLKEM1024 d, GroupPubA_MLKEM1024 e)
groupGenerateKeyPair X25519MLKEM768 = do
    (d1, e1) <- fs' $ curveGenerateKeyPair x25519
    (e2, d2) <- ML.generate mlkem768
    return (GroupPri_X25519MLKEM768 (d1, d2), GroupPubA_X25519MLKEM768 (e1, e2))
groupGenerateKeyPair P256MLKEM768 = do
    (d1, e1) <- fs' $ curveGenerateKeyPair p256
    (e2, d2) <- ML.generate mlkem768
    return (GroupPri_P256MLKEM768 (d1, d2), GroupPubA_P256MLKEM768 (e1, e2))
groupGenerateKeyPair P384MLKEM1024 = do
    (d1, e1) <- fs' $ curveGenerateKeyPair p384
    (e2, d2) <- ML.generate mlkem1024
    return (GroupPri_P384MLKEM1024 (d1, d2), GroupPubA_P384MLKEM1024 (e1, e2))
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
    => (Scalar a -> GroupPrivate, Point a -> GroupPublicA)
    -> r (KeyPair a)
    -> r (GroupPrivate, GroupPublicA)
(t1, t2) `fs` action = do
    keypair <- action
    let pub = keypairGetPublic keypair
        pri = keypairGetPrivate keypair
    return (t1 pri, t2 pub)

fs' :: Monad m => m (KeyPair curve) -> m (Scalar curve, Point curve)
fs' action = do
    keypair <- action
    let pub = keypairGetPublic keypair
        pri = keypairGetPrivate keypair
    return (pri, pub)

gen
    :: MonadRandom r
    => DH.Params
    -> Int
    -> (PrivateNumber -> GroupPrivate)
    -> (PublicNumber -> GroupPublicA)
    -> r (GroupPrivate, GroupPublicA)
gen params expBits priTag pubTag = (priTag *** pubTag) <$> gen' params expBits

gen'
    :: MonadRandom r
    => DH.Params
    -> Int
    -> r (PrivateNumber, PublicNumber)
gen' params expBits = (id &&& DH.calculatePublic params) <$> generatePriv expBits

groupEncapsulate
    :: MonadRandom r => GroupPublicA -> r (Maybe (GroupPublicB, GroupKey))
groupEncapsulate (GroupPubA_P256 pub) = getECDHPubShared GroupPubB_P256 p256 pub
groupEncapsulate (GroupPubA_P384 pub) = getECDHPubShared GroupPubB_P384 p384 pub
groupEncapsulate (GroupPubA_P521 pub) = getECDHPubShared GroupPubB_P521 p521 pub
groupEncapsulate (GroupPubA_X255 pub) = getECDHPubShared GroupPubB_X255 x25519 pub
groupEncapsulate (GroupPubA_X448 pub) = getECDHPubShared GroupPubB_X448 x448 pub
groupEncapsulate (GroupPubA_FFDHE2048 pub) = getDHPubShared ffdhe2048 exp2048 pub GroupPubB_FFDHE2048
groupEncapsulate (GroupPubA_FFDHE3072 pub) = getDHPubShared ffdhe3072 exp3072 pub GroupPubB_FFDHE3072
groupEncapsulate (GroupPubA_FFDHE4096 pub) = getDHPubShared ffdhe4096 exp4096 pub GroupPubB_FFDHE4096
groupEncapsulate (GroupPubA_FFDHE6144 pub) = getDHPubShared ffdhe6144 exp6144 pub GroupPubB_FFDHE6144
groupEncapsulate (GroupPubA_FFDHE8192 pub) = getDHPubShared ffdhe8192 exp8192 pub GroupPubB_FFDHE8192
groupEncapsulate (GroupPubA_MLKEM512 pub) = do
    (sec, ct) <- ML.encapsulate pub
    return $ Just (GroupPubB_MLKEM512 ct, B.convert sec)
groupEncapsulate (GroupPubA_MLKEM768 pub) = do
    (sec, ct) <- ML.encapsulate pub
    return $ Just (GroupPubB_MLKEM768 ct, B.convert sec)
groupEncapsulate (GroupPubA_MLKEM1024 pub) = do
    (sec, ct) <- ML.encapsulate pub
    return $ Just (GroupPubB_MLKEM1024 ct, B.convert sec)
groupEncapsulate (GroupPubA_X25519MLKEM768 (e1, e2)) = do
    (c1, k1) <- fromJust <$> getECDHPubShared' x25519 e1
    (k2, c2) <- ML.encapsulate e2
    -- Sec 4.1: Specifically, the order of shares in the concatenation
    -- has been reversed.
    return $ Just (GroupPubB_X25519MLKEM768 (c1, c2), B.convert k2 <> k1)
groupEncapsulate (GroupPubA_P256MLKEM768 (e1, e2)) = do
    (c1, k1) <- fromJust <$> getECDHPubShared' p256 e1
    (k2, c2) <- ML.encapsulate e2
    return $ Just (GroupPubB_P256MLKEM768 (c1, c2), k1 <> B.convert k2)
groupEncapsulate (GroupPubA_P384MLKEM1024 (e1, e2)) = do
    (c1, k1) <- fromJust <$> getECDHPubShared' p384 e1
    (k2, c2) <- ML.encapsulate e2
    return $ Just (GroupPubB_P384MLKEM1024 (c1, c2), k1 <> B.convert k2)

dhGroupGetPubShared
    :: MonadRandom r => Group -> PublicNumber -> r (Maybe (PublicNumber, GroupKey))
dhGroupGetPubShared FFDHE2048 pub = getDHPubShared' ffdhe2048 exp2048 pub
dhGroupGetPubShared FFDHE3072 pub = getDHPubShared' ffdhe3072 exp3072 pub
dhGroupGetPubShared FFDHE4096 pub = getDHPubShared' ffdhe4096 exp4096 pub
dhGroupGetPubShared FFDHE6144 pub = getDHPubShared' ffdhe6144 exp6144 pub
dhGroupGetPubShared FFDHE8192 pub = getDHPubShared' ffdhe8192 exp8192 pub
dhGroupGetPubShared _ _ = return Nothing

getECDHPubShared
    :: (MonadRandom m, EllipticCurveDH curve)
    => (Point curve -> GroupPublicB)
    -> proxy curve
    -> Point curve
    -> m (Maybe (GroupPublicB, GroupKey))
getECDHPubShared tag proxy pub = do
    mx <- maybeCryptoError <$> deriveEncrypt proxy pub
    case mx of
        Nothing -> return Nothing
        Just (p, s) -> return $ Just (tag p, B.convert s)

getECDHPubShared'
    :: (MonadRandom m, EllipticCurveDH curve)
    => proxy curve
    -> Point curve
    -> m (Maybe (Point curve, GroupKey))
getECDHPubShared' proxy pub = do
    mx <- maybeCryptoError <$> deriveEncrypt proxy pub
    case mx of
        Nothing -> return Nothing
        Just (p, s) -> return $ Just (p, B.convert s)

getDHPubShared
    :: MonadRandom r
    => DH.Params
    -> Int
    -> PublicNumber
    -> (PublicNumber -> GroupPublicB)
    -> r (Maybe (GroupPublicB, GroupKey))
getDHPubShared params expBits pub pubTag
    | not (valid params pub) = return Nothing
    | otherwise = do
        mypri <- generatePriv expBits
        let mypub = DH.calculatePublic params mypri
            share = DH.getShared params mypri pub
        return $ Just (pubTag mypub, B.convert share)

getDHPubShared'
    :: MonadRandom r
    => DH.Params
    -> Int
    -> PublicNumber
    -> r (Maybe (PublicNumber, GroupKey))
getDHPubShared' params expBits pub
    | not (valid params pub) = return Nothing
    | otherwise = do
        mypri <- generatePriv expBits
        let share = stripLeadingZeros (DH.getShared params mypri pub)
        return $ Just (DH.calculatePublic params mypri, B.convert share)

groupDecapsulate :: GroupPublicB -> GroupPrivate -> Maybe GroupKey
groupDecapsulate (GroupPubB_P256 pub) (GroupPri_P256 pri) = (B.convert <$>) . maybeCryptoError $ deriveDecrypt p256 pub pri
groupDecapsulate (GroupPubB_P384 pub) (GroupPri_P384 pri) = (B.convert <$>) . maybeCryptoError $ deriveDecrypt p384 pub pri
groupDecapsulate (GroupPubB_P521 pub) (GroupPri_P521 pri) = (B.convert <$>) . maybeCryptoError $ deriveDecrypt p521 pub pri
groupDecapsulate (GroupPubB_X255 pub) (GroupPri_X255 pri) = (B.convert <$>) . maybeCryptoError $ deriveDecrypt x25519 pub pri
groupDecapsulate (GroupPubB_X448 pub) (GroupPri_X448 pri) = (B.convert <$>) . maybeCryptoError $ deriveDecrypt x448 pub pri
groupDecapsulate (GroupPubB_FFDHE2048 pub) (GroupPri_FFDHE2048 pri) = calcDHShared ffdhe2048 pub pri
groupDecapsulate (GroupPubB_FFDHE3072 pub) (GroupPri_FFDHE3072 pri) = calcDHShared ffdhe3072 pub pri
groupDecapsulate (GroupPubB_FFDHE4096 pub) (GroupPri_FFDHE4096 pri) = calcDHShared ffdhe4096 pub pri
groupDecapsulate (GroupPubB_FFDHE6144 pub) (GroupPri_FFDHE6144 pri) = calcDHShared ffdhe6144 pub pri
groupDecapsulate (GroupPubB_FFDHE8192 pub) (GroupPri_FFDHE8192 pri) = calcDHShared ffdhe8192 pub pri
groupDecapsulate (GroupPubB_MLKEM512 p) (GroupPri_MLKEM512 s) =
    Just $ B.convert $ ML.decapsulate s p
groupDecapsulate (GroupPubB_MLKEM768 p) (GroupPri_MLKEM768 s) =
    Just $ B.convert $ ML.decapsulate s p
groupDecapsulate (GroupPubB_MLKEM1024 p) (GroupPri_MLKEM1024 s) =
    Just $ B.convert $ ML.decapsulate s p
groupDecapsulate (GroupPubB_X25519MLKEM768 (p1, p2)) (GroupPri_X25519MLKEM768 (s1, s2)) = do
    bs1 <- (B.convert <$>) . maybeCryptoError $ deriveDecrypt x25519 p1 s1
    let bs2 = B.convert $ ML.decapsulate s2 p2
    return (bs2 <> bs1)
groupDecapsulate (GroupPubB_P256MLKEM768 (p1, p2)) (GroupPri_P256MLKEM768 (s1, s2)) = do
    bs1 <- (B.convert <$>) . maybeCryptoError $ deriveDecrypt p256 p1 s1
    let bs2 = B.convert $ ML.decapsulate s2 p2
    return (bs1 <> bs2)
groupDecapsulate (GroupPubB_P384MLKEM1024 (p1, p2)) (GroupPri_P384MLKEM1024 (s1, s2)) = do
    bs1 <- (B.convert <$>) . maybeCryptoError $ deriveDecrypt p384 p1 s1
    let bs2 = B.convert $ ML.decapsulate s2 p2
    return (bs1 <> bs2)
groupDecapsulate _ _ = Nothing

calcDHShared :: DH.Params -> PublicNumber -> PrivateNumber -> Maybe GroupKey
calcDHShared params pub pri
    | valid params pub = Just $ B.convert share
    | otherwise = Nothing
  where
    share = DH.getShared params pri pub

groupEncodePublicA :: GroupPublicA -> ByteString
groupEncodePublicA (GroupPubA_P256 p) = encodePoint p256 p
groupEncodePublicA (GroupPubA_P384 p) = encodePoint p384 p
groupEncodePublicA (GroupPubA_P521 p) = encodePoint p521 p
groupEncodePublicA (GroupPubA_X255 p) = encodePoint x25519 p
groupEncodePublicA (GroupPubA_X448 p) = encodePoint x448 p
groupEncodePublicA (GroupPubA_FFDHE2048 p) = enc ffdhe2048 p
groupEncodePublicA (GroupPubA_FFDHE3072 p) = enc ffdhe3072 p
groupEncodePublicA (GroupPubA_FFDHE4096 p) = enc ffdhe4096 p
groupEncodePublicA (GroupPubA_FFDHE6144 p) = enc ffdhe6144 p
groupEncodePublicA (GroupPubA_FFDHE8192 p) = enc ffdhe8192 p
groupEncodePublicA (GroupPubA_MLKEM512 p) = ML.encode p
groupEncodePublicA (GroupPubA_MLKEM768 p) = ML.encode p
groupEncodePublicA (GroupPubA_MLKEM1024 p) = ML.encode p
groupEncodePublicA (GroupPubA_X25519MLKEM768 (p1, p2)) =
    ML.encode p2 <> encodePoint x25519 p1
groupEncodePublicA (GroupPubA_P256MLKEM768 (p1, p2)) =
    encodePoint p256 p1 <> ML.encode p2
groupEncodePublicA (GroupPubA_P384MLKEM1024 (p1, p2)) =
    encodePoint p384 p1 <> ML.encode p2

groupEncodePublicB :: GroupPublicB -> ByteString
groupEncodePublicB (GroupPubB_P256 p) = encodePoint p256 p
groupEncodePublicB (GroupPubB_P384 p) = encodePoint p384 p
groupEncodePublicB (GroupPubB_P521 p) = encodePoint p521 p
groupEncodePublicB (GroupPubB_X255 p) = encodePoint x25519 p
groupEncodePublicB (GroupPubB_X448 p) = encodePoint x448 p
groupEncodePublicB (GroupPubB_FFDHE2048 p) = enc ffdhe2048 p
groupEncodePublicB (GroupPubB_FFDHE3072 p) = enc ffdhe3072 p
groupEncodePublicB (GroupPubB_FFDHE4096 p) = enc ffdhe4096 p
groupEncodePublicB (GroupPubB_FFDHE6144 p) = enc ffdhe6144 p
groupEncodePublicB (GroupPubB_FFDHE8192 p) = enc ffdhe8192 p
groupEncodePublicB (GroupPubB_MLKEM512 p) = B.convert p
groupEncodePublicB (GroupPubB_MLKEM768 p) = B.convert p
groupEncodePublicB (GroupPubB_MLKEM1024 p) = B.convert p
groupEncodePublicB (GroupPubB_X25519MLKEM768 (p1, p2)) =
    B.convert p2 <> encodePoint x25519 p1
groupEncodePublicB (GroupPubB_P256MLKEM768 (p1, p2)) =
    encodePoint p256 p1 <> B.convert p2
groupEncodePublicB (GroupPubB_P384MLKEM1024 (p1, p2)) =
    encodePoint p384 p1 <> B.convert p2

enc :: DH.Params -> PublicNumber -> ByteString
enc params (PublicNumber p) = i2ospOf_ ((DH.params_bits params + 7) `div` 8) p

groupDecodePublicA :: Group -> ByteString -> Either CryptoError GroupPublicA
groupDecodePublicA P256 bs = eitherCryptoError $ GroupPubA_P256 <$> decodePoint p256 bs
groupDecodePublicA P384 bs = eitherCryptoError $ GroupPubA_P384 <$> decodePoint p384 bs
groupDecodePublicA P521 bs = eitherCryptoError $ GroupPubA_P521 <$> decodePoint p521 bs
groupDecodePublicA X25519 bs = eitherCryptoError $ GroupPubA_X255 <$> decodePoint x25519 bs
groupDecodePublicA X448 bs = eitherCryptoError $ GroupPubA_X448 <$> decodePoint x448 bs
groupDecodePublicA FFDHE2048 bs = Right . GroupPubA_FFDHE2048 . PublicNumber $ os2ip bs
groupDecodePublicA FFDHE3072 bs = Right . GroupPubA_FFDHE3072 . PublicNumber $ os2ip bs
groupDecodePublicA FFDHE4096 bs = Right . GroupPubA_FFDHE4096 . PublicNumber $ os2ip bs
groupDecodePublicA FFDHE6144 bs = Right . GroupPubA_FFDHE6144 . PublicNumber $ os2ip bs
groupDecodePublicA FFDHE8192 bs = Right . GroupPubA_FFDHE8192 . PublicNumber $ os2ip bs
groupDecodePublicA MLKEM512 bs = case ML.decode mlkem512 bs of
    Nothing -> Left CryptoError_PointFormatInvalid
    Just p -> Right $ GroupPubA_MLKEM512 p
groupDecodePublicA MLKEM768 bs = case ML.decode mlkem768 bs of
    Nothing -> Left CryptoError_PointFormatInvalid
    Just p -> Right $ GroupPubA_MLKEM768 p
groupDecodePublicA MLKEM1024 bs = case ML.decode mlkem1024 bs of
    Nothing -> Left CryptoError_PointFormatInvalid
    Just p -> Right $ GroupPubA_MLKEM1024 p
groupDecodePublicA X25519MLKEM768 bs =
    let (bs1, bs2) = BS.splitAt 1184 bs
     in case ML.decode mlkem768 bs1 of
            Nothing -> Left CryptoError_PointFormatInvalid
            Just p1 -> case maybeCryptoError $ decodePoint x25519 bs2 of
                Nothing -> Left CryptoError_PointFormatInvalid
                Just p2 -> Right $ GroupPubA_X25519MLKEM768 (p2, p1)
groupDecodePublicA P256MLKEM768 bs =
    let (bs1, bs2) = BS.splitAt 65 bs
     in case ML.decode mlkem768 bs2 of
            Nothing -> Left CryptoError_PointFormatInvalid
            Just p1 -> case maybeCryptoError $ decodePoint p256 bs1 of
                Nothing -> Left CryptoError_PointFormatInvalid
                Just p2 -> Right $ GroupPubA_P256MLKEM768 (p2, p1)
groupDecodePublicA P384MLKEM1024 bs =
    let (bs1, bs2) = BS.splitAt 97 bs
     in case ML.decode mlkem1024 bs2 of
            Nothing -> Left CryptoError_PointFormatInvalid
            Just p1 -> case maybeCryptoError $ decodePoint p384 bs1 of
                Nothing -> Left CryptoError_PointFormatInvalid
                Just p2 -> Right $ GroupPubA_P384MLKEM1024 (p2, p1)
groupDecodePublicA _ _ = error "groupDecodePublicA"

groupDecodePublicB :: Group -> ByteString -> Either CryptoError GroupPublicB
groupDecodePublicB P256 bs = eitherCryptoError $ GroupPubB_P256 <$> decodePoint p256 bs
groupDecodePublicB P384 bs = eitherCryptoError $ GroupPubB_P384 <$> decodePoint p384 bs
groupDecodePublicB P521 bs = eitherCryptoError $ GroupPubB_P521 <$> decodePoint p521 bs
groupDecodePublicB X25519 bs = eitherCryptoError $ GroupPubB_X255 <$> decodePoint x25519 bs
groupDecodePublicB X448 bs = eitherCryptoError $ GroupPubB_X448 <$> decodePoint x448 bs
groupDecodePublicB FFDHE2048 bs = Right . GroupPubB_FFDHE2048 . PublicNumber $ os2ip bs
groupDecodePublicB FFDHE3072 bs = Right . GroupPubB_FFDHE3072 . PublicNumber $ os2ip bs
groupDecodePublicB FFDHE4096 bs = Right . GroupPubB_FFDHE4096 . PublicNumber $ os2ip bs
groupDecodePublicB FFDHE6144 bs = Right . GroupPubB_FFDHE6144 . PublicNumber $ os2ip bs
groupDecodePublicB FFDHE8192 bs = Right . GroupPubB_FFDHE8192 . PublicNumber $ os2ip bs
groupDecodePublicB MLKEM512 bs = case ML.decode mlkem512 bs of
    Nothing -> Left CryptoError_PointFormatInvalid
    Just p -> Right $ GroupPubB_MLKEM512 p
groupDecodePublicB MLKEM768 bs = case ML.decode mlkem768 bs of
    Nothing -> Left CryptoError_PointFormatInvalid
    Just p -> Right $ GroupPubB_MLKEM768 p
groupDecodePublicB MLKEM1024 bs = case ML.decode mlkem1024 bs of
    Nothing -> Left CryptoError_PointFormatInvalid
    Just p -> Right $ GroupPubB_MLKEM1024 p
groupDecodePublicB X25519MLKEM768 bs =
    let (bs1, bs2) = BS.splitAt 1088 bs
     in case ML.decode mlkem768 bs1 of
            Nothing -> Left CryptoError_PointFormatInvalid
            Just p1 -> case maybeCryptoError $ decodePoint x25519 bs2 of
                Nothing -> Left CryptoError_PointFormatInvalid
                Just p2 -> Right $ GroupPubB_X25519MLKEM768 (p2, p1)
groupDecodePublicB P256MLKEM768 bs =
    let (bs1, bs2) = BS.splitAt 65 bs
     in case ML.decode mlkem768 bs2 of
            Nothing -> Left CryptoError_PointFormatInvalid
            Just p1 -> case maybeCryptoError $ decodePoint p256 bs1 of
                Nothing -> Left CryptoError_PointFormatInvalid
                Just p2 -> Right $ GroupPubB_P256MLKEM768 (p2, p1)
groupDecodePublicB P384MLKEM1024 bs =
    let (bs1, bs2) = BS.splitAt 97 bs
     in case ML.decode mlkem1024 bs2 of
            Nothing -> Left CryptoError_PointFormatInvalid
            Just p1 -> case maybeCryptoError $ decodePoint p384 bs1 of
                Nothing -> Left CryptoError_PointFormatInvalid
                Just p2 -> Right $ GroupPubB_P384MLKEM1024 (p2, p1)
groupDecodePublicB _ _ = error "groupDecodePublicB"

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
