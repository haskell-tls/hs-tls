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
    , dhGenerateKeyPair
    , dhGetShared
    , dhUnwrap
    , dhUnwrapPublic
    ) where

import Network.TLS.Util.Serialization (i2osp)
import qualified Crypto.PubKey.DH as DH
import Network.TLS.RNG
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

dhGenerateKeyPair :: MonadRandom r => DHParams -> r (DHPrivate, DHPublic)
dhGenerateKeyPair params = do
    priv <- DH.generatePrivate params
    let pub        = DH.generatePublic params priv
    return (priv, pub)

dhGetShared :: DHParams -> DHPrivate -> DHPublic -> DHKey
dhGetShared params priv pub =
    let (DH.SharedKey sk) = DH.getShared params priv pub
     in i2osp sk

dhUnwrap :: DHParams -> DHPublic -> [Integer]
dhUnwrap (DH.Params p g) (DH.PublicNumber y) = [p,g,y]

dhUnwrapPublic :: DHPublic -> Integer
dhUnwrapPublic (DH.PublicNumber y) = y
