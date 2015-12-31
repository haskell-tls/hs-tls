module ClientConfig (
  prop_setCiphers
) where

import Control.Applicative ((<$>), (<*>))
import qualified Data.ByteString.Char8 as BC
import Network.TLS.ClientConfig (
  Cipher, ciphersuite_all, ClientParams(..), Default(def),
  defaultParamsClient,
  setCiphers)
import qualified Network.TLS as TLS
import Test.QuickCheck (Arbitrary(arbitrary), elements)

instance Arbitrary Cipher where
  arbitrary = elements ciphersuite_all

instance Arbitrary BC.ByteString where
  arbitrary = BC.pack <$> arbitrary

instance Arbitrary ClientParams where
  arbitrary = defaultParamsClient <$> arbitrary <*> arbitrary

prop_setCiphers :: [Cipher] -> ClientParams -> Bool
prop_setCiphers ciphers cp = (TLS.supportedCiphers $ clientSupported $ setCiphers ciphers cp) == ciphers
