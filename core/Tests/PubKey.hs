module PubKey
    ( arbitraryRSAPair
    , arbitraryDSAPair
    , arbitraryECDSAPair
    , arbitraryEd25519Pair
    , arbitraryEd448Pair
    , globalRSAPair
    , getGlobalRSAPair
    , knownECCurves
    , defaultECCurve
    , dhParams512
    , dhParams768
    , dhParams1024
    , dsaParams
    , rsaParams
    ) where

import Test.Tasty.QuickCheck

import qualified Data.ByteString as B
import qualified Crypto.PubKey.DH as DH
import Crypto.Error
import Crypto.Random
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Prim  as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448

import Control.Concurrent.MVar
import System.IO.Unsafe

arbitraryRSAPair :: Gen (RSA.PublicKey, RSA.PrivateKey)
arbitraryRSAPair = (rngToRSA . drgNewTest) `fmap` arbitrary
  where
    rngToRSA :: ChaChaDRG -> (RSA.PublicKey, RSA.PrivateKey)
    rngToRSA rng = fst $ withDRG rng arbitraryRSAPairWithRNG

arbitraryRSAPairWithRNG :: MonadRandom m => m (RSA.PublicKey, RSA.PrivateKey)
arbitraryRSAPairWithRNG = RSA.generate 256 0x10001

{-# NOINLINE globalRSAPair #-}
globalRSAPair :: MVar (RSA.PublicKey, RSA.PrivateKey)
globalRSAPair = unsafePerformIO $ do
    drg <- drgNew
    newMVar (fst $ withDRG drg arbitraryRSAPairWithRNG)

{-# NOINLINE getGlobalRSAPair #-}
getGlobalRSAPair :: (RSA.PublicKey, RSA.PrivateKey)
getGlobalRSAPair = unsafePerformIO (readMVar globalRSAPair)

rsaParams :: (RSA.PublicKey, RSA.PrivateKey)
rsaParams = (pub, priv)
 where priv = RSA.PrivateKey { RSA.private_pub  = pub
                             , RSA.private_d    = d
                             , RSA.private_p    = 0
                             , RSA.private_q    = 0
                             , RSA.private_dP   = 0
                             , RSA.private_dQ   = 0
                             , RSA.private_qinv = 0
                             }
       pub = RSA.PublicKey { RSA.public_size = (1024 `div` 8), RSA.public_n = n, RSA.public_e = e }
       n = 0x00c086b4c6db28ae578d73766d6fdd04b913808a85bf9ad7bcfc9a6ff04d13d2ff75f761ce7db9ee8996e29dc433d19a2d3f748e8d368ba099781d58276e1863a324ae3fb1a061874cd9f3510e54e49727c68de0616964335371cfb63f15ebff8ce8df09c74fb8625f8f58548b90f079a3405f522e738e664d0c645b015664f7c7
       e = 0x10001
       d = 0x3edc3cae28e4717818b1385ba7088d0038c3e176a606d2a5dbfc38cc46fe500824e62ec312fde04a803f61afac13a5b95c5c9c26b346879b54429083df488b4f29bb7b9722d366d6f5d2b512150a2e950eacfe0fd9dd56b87b0322f74ae3c8d8674ace62bc723f7c05e9295561efd70d7a924c6abac2e482880fc0149d5ad481

dhParams512 :: DH.Params
dhParams512 = DH.Params
    { DH.params_p = 0x00ccaa3884b50789ebea8d39bef8bbc66e20f2a78f537a76f26b4edde5de8b0ff15a8193abf0873cbdc701323a2bf6e860affa6e043fe8300d47e95baf9f6354cb
    , DH.params_g = 0x2
    , DH.params_bits = 512
    }

-- from RFC 2409

dhParams768 :: DH.Params
dhParams768 = DH.Params
    { DH.params_p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff
    , DH.params_g = 0x2
    , DH.params_bits = 768
    }

dhParams1024 :: DH.Params
dhParams1024 = DH.Params
    { DH.params_p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff
    , DH.params_g = 0x2
    , DH.params_bits = 1024
    }

dsaParams :: DSA.Params
dsaParams = DSA.Params
    { DSA.params_p = 0x009f356bbc4750645555b02aa3918e85d5e35bdccd56154bfaa3e1801d5fe0faf65355215148ea866d5732fd27eb2f4d222c975767d2eb573513e460eceae327c8ac5da1f4ce765c49a39cae4c904b4e5cc64554d97148f20a2655027a0cf8f70b2550cc1f0c9861ce3a316520ab0588407ea3189d20c78bd52df97e56cbe0bbeb
    , DSA.params_q = 0x00f33a57b47de86ff836f9fe0bb060c54ab293133b
    , DSA.params_g = 0x3bb973c4f6eee92d1530f250487735595d778c2e5c8147d67a46ebcba4e6444350d49da8e7da667f9b1dbb22d2108870b9fcfabc353cdfac5218d829f22f69130317cc3b0d724881e34c34b8a2571d411da6458ef4c718df9e826f73e16a035b1dcbc1c62cac7a6604adb3e7930be8257944c6dfdddd655004b98253185775ff
    }

arbitraryDSAPair :: Gen (DSA.PublicKey, DSA.PrivateKey)
arbitraryDSAPair = do
    priv <- choose (1, DSA.params_q dsaParams)
    let pub = DSA.calculatePublic dsaParams priv
    return (DSA.PublicKey dsaParams pub, DSA.PrivateKey dsaParams priv)

-- for performance reason P521 is not tested
knownECCurves :: [ECC.CurveName]
knownECCurves = [ ECC.SEC_p256r1
                , ECC.SEC_p384r1
                ]

defaultECCurve :: ECC.CurveName
defaultECCurve = ECC.SEC_p256r1

arbitraryECDSAPair :: ECC.CurveName -> Gen (ECDSA.PublicKey, ECDSA.PrivateKey)
arbitraryECDSAPair curveName = do
    d <- choose (1, n - 1)
    let p = ECC.pointBaseMul curve d
    return (ECDSA.PublicKey curve p, ECDSA.PrivateKey curve d)
  where
    curve = ECC.getCurveByName curveName
    n     = ECC.ecc_n . ECC.common_curve $ curve

arbitraryEd25519Pair :: Gen (Ed25519.PublicKey, Ed25519.SecretKey)
arbitraryEd25519Pair = do
    bytes <- vectorOf 32 arbitrary
    let CryptoPassed priv = Ed25519.secretKey (B.pack bytes)
    return (Ed25519.toPublic priv, priv)

arbitraryEd448Pair :: Gen (Ed448.PublicKey, Ed448.SecretKey)
arbitraryEd448Pair = do
    bytes <- vectorOf 57 arbitrary
    let CryptoPassed priv = Ed448.secretKey (B.pack bytes)
    return (Ed448.toPublic priv, priv)
