module Network.TLS.Crypto.DH
    (
    -- * DH types
      DHParams
    , DHPublic
    , DHPrivate

    -- * DH methods
    , dhPublic
    , dhPrivate
    , dhParams
    , dhParamsGetP
    , dhParamsGetG
    , dhGenerateKeyPair
    , dhGetShared
    , dhUnwrap
    , dhUnwrapPublic
    ) where

import Network.TLS.Util.Serialization (i2osp)
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.Types.PubKey.DH as DH
import Crypto.Random (CPRG)
import Data.ByteString (ByteString)

type DHPublic   = DH.PublicNumber
type DHPrivate  = DH.PrivateNumber
type DHParams   = DH.Params
type DHKey      = ByteString

dhPublic :: Integer -> DHPublic
dhPublic = DH.PublicNumber

dhPrivate :: Integer -> DHPrivate
dhPrivate = DH.PrivateNumber

dhParams :: Integer -> Integer -> DHParams
dhParams = DH.Params

dhGenerateKeyPair :: CPRG g => g -> DHParams -> ((DHPrivate, DHPublic), g)
dhGenerateKeyPair rng params =
    let (priv, g') = DH.generatePrivate rng params
        pub        = DH.generatePublic params priv
     in ((priv, pub), g')

dhGetShared :: DHParams -> DHPrivate -> DHPublic -> DHKey
dhGetShared params priv pub =
    let (DH.SharedKey sk) = DH.getShared params priv pub
     in i2osp sk

dhUnwrap :: DHParams -> DHPublic -> [Integer]
dhUnwrap (DH.Params p g) (DH.PublicNumber y) = [p,g,y]

dhParamsGetP :: DHParams -> Integer
dhParamsGetP (DH.Params p _) = p

dhParamsGetG :: DHParams -> Integer
dhParamsGetG (DH.Params _ g) = g

dhUnwrapPublic :: DHPublic -> Integer
dhUnwrapPublic (DH.PublicNumber y) = y
