{-# LANGUAGE BangPatterns #-}

module Network.TLS.Crypto.ECDH
    (
    -- * ECDH types
      ECDHParams(..)
    , ECDHPublic
    , ECDHKeyPair
    , ECDH.CurveKeyPair(..)
    -- * ECDH methods
    , ecdhPublic
    , fromECDHKeyPair
    , ecdhParams
    , ecdhGenerateKeyPair
    , ecdhGetShared
    , ecdhUnwrap
    , ecdhUnwrapPublic
    ) where

import Network.TLS.Util.Serialization (lengthBytes)
import Network.TLS.Extension.EC
import qualified Crypto.PubKey.ECC.DH as ECDH
import Network.TLS.RNG
import Data.Word (Word16)

data ECDHPublic = ECDHPublic (Integer,Integer) !Int -- byte size
     deriving (Show,Eq)

type ECDHKeyPair = ECDH.CurveKeyPair

data ECDHParams = ECDHParams ECDH.Curve !Word16 deriving (Show,Eq)

type ECDHKey = ECDH.SharedSecret

ecdhPublic :: Integer -> Integer -> Int -> ECDHPublic
ecdhPublic x y siz = ECDHPublic (x,y) siz

fromECDHKeyPair :: ECDHKeyPair -> ECDHPublic
fromECDHKeyPair (ECDH.CurveKeyPair kp) = ECDHPublic xy siz
  where
    p = ECDH.keypairPublic kp
    xy = ECDH.curvePointToIntegers p
    siz = ECDH.curveBytes (ECDH.curveOfPoint p)

ecdhParams :: Word16 -> ECDHParams
ecdhParams 23 = ECDHParams (ECDH.Curve ECDH.Curve_P256R1) 23
ecdhParams 25 = ECDHParams (ECDH.Curve ECDH.Curve_P521R1) 25
ecdhParams _  = ECDHParams undefined undefined -- fixme

ecdhGenerateKeyPair :: MonadRandom r => ECDHParams -> r ECDH.CurveKeyPair
ecdhGenerateKeyPair (ECDHParams curve _) = ECDH.generateKeyPair curve

ecdhGetShared :: ECDHParams -> ECDH.CurveKeyPair -> ECDHPublic -> Maybe ECDHKey
ecdhGetShared (ECDHParams (ECDH.Curve c) _) kp (ECDHPublic xy@(x,y) _)
  | ECDH.curveIsPointValid p = Just $ ECDH.getShared xy kp
  | otherwise                = Nothing
  where
    p = ECDH.curveIntegersToPoint c x y

-- for server key exchange
ecdhUnwrap :: ECDHParams -> ECDHPublic -> (Word16,Integer,Integer,Int)
ecdhUnwrap (ECDHParams _ w16) (ECDHPublic (x,y) siz) = (w16,x,y,siz)

-- for client key exchange
ecdhUnwrapPublic :: ECDHPublic -> (Integer,Integer,Int)
ecdhUnwrapPublic (ECDHPublic (x,y) siz) = (x,y,siz)
