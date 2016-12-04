module Network.TLS.Crypto.ECDH
    (
    -- * ECDH types
      ECDHParams(..)
    , ECDHPublic
    , ECDHPrivate(..)

    -- * ECDH methods
    , ecdhPublic
    , ecdhPrivate
    , ecdhParams
    , ecdhGenerateKeyPair
    , ecdhGetShared
    , ecdhUnwrap
    , ecdhUnwrapPublic
    ) where

import Network.TLS.Extension.EC
import qualified Crypto.PubKey.ECC.DH as ECDH
import qualified Crypto.PubKey.ECC.Types as ECDH
import qualified Crypto.PubKey.ECC.Prim as ECC (isPointValid)
import Network.TLS.RNG
import Data.Word (Word16)

data ECDHPublic = ECDHPublic ECDH.PublicPoint Int {- byte size -}
    deriving (Show,Eq)

newtype ECDHPrivate = ECDHPrivate ECDH.PrivateNumber deriving (Show,Eq)

data ECDHParams = ECDHParams ECDH.Curve ECDH.CurveName deriving (Show,Eq)

type ECDHKey = ECDH.SharedKey

ecdhPublic :: Integer -> Integer -> Int -> ECDHPublic
ecdhPublic x y siz = ECDHPublic (ECDH.Point x y) siz

ecdhPrivate :: Integer -> ECDHPrivate
ecdhPrivate = ECDHPrivate

ecdhParams :: Word16 -> ECDHParams
ecdhParams w16 = ECDHParams curve name
  where
    Just name = toCurveName w16 -- FIXME
    curve = ECDH.getCurveByName name

ecdhGenerateKeyPair :: MonadRandom r => ECDHParams -> r (ECDHPrivate, ECDHPublic)
ecdhGenerateKeyPair (ECDHParams curve _) = do
    priv <- ECDH.generatePrivate curve
    let siz        = pointSize curve
        point      = ECDH.calculatePublic curve priv
        pub        = ECDHPublic point siz
    return (ECDHPrivate priv, pub)

ecdhGetShared :: ECDHParams -> ECDHPrivate -> ECDHPublic -> Maybe ECDHKey
ecdhGetShared (ECDHParams curve _)  (ECDHPrivate priv) (ECDHPublic point _)
    | ECC.isPointValid curve point = Just $ ECDH.getShared curve priv point
    | otherwise                    = Nothing

-- for server key exchange
ecdhUnwrap :: ECDHParams -> ECDHPublic -> (Word16,Integer,Integer,Int)
ecdhUnwrap (ECDHParams _ name) point = (w16,x,y,siz)
  where
    w16 = case fromCurveName name of
        Just w  -> w
        Nothing -> error "ecdhUnwrap"
    (x,y,siz) = ecdhUnwrapPublic point

-- for client key exchange
ecdhUnwrapPublic :: ECDHPublic -> (Integer,Integer,Int)
ecdhUnwrapPublic (ECDHPublic (ECDH.Point x y) siz) = (x,y,siz)
ecdhUnwrapPublic _                                 = error "ecdhUnwrapPublic"

pointSize :: ECDH.Curve -> Int
pointSize = toBytes . ECDH.curveSizeBits
  where
    toBytes bits = (bits + 7) `div` 8
