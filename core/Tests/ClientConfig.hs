module ClientConfig (
  prop_setCiphers,
  prop_setCA,
  prop_setServerValidator
) where

import Control.Applicative ((<$>), (<*>))
import Data.Monoid (mempty)
import qualified Data.ByteString.Char8 as BC
import Network.TLS.ClientConfig (
  Cipher, ciphersuite_all, ClientParams(..), Default(def),
  defaultParamsClient,
  setCiphers, setCA, setServerValidator,
  makeCertificateStore, listCertificates)
import qualified Network.TLS as TLS
import Test.QuickCheck (Arbitrary(arbitrary), elements, oneof)
import Test.QuickCheck.Monadic (PropertyM, run, pick, assert)
import Data.X509.Validation (FailedReason(..))
import Data.X509 (CertificateChain(..))

instance Arbitrary Cipher where
  arbitrary = elements ciphersuite_all

instance Arbitrary BC.ByteString where
  arbitrary = BC.pack <$> arbitrary

instance Arbitrary ClientParams where
  arbitrary = defaultParamsClient <$> arbitrary <*> arbitrary

instance Arbitrary FailedReason where
  arbitrary = oneof $ map return [
    UnknownCriticalExtension,
    Expired,
    InFuture,
    SelfSigned,
    UnknownCA,
    NotAllowedToSign,
    NotAnAuthority,
    AuthorityTooDeep,
    NoCommonName,
    InvalidWildcard,
    LeafKeyUsageNotAllowed,
    LeafKeyPurposeNotAllowed,
    LeafNotV3,
    EmptyChain
    ] ++ map (<$> arbitrary) [InvalidName, NameMismatch, CacheSaysNo]


prop_setCiphers :: [Cipher] -> ClientParams -> Bool
prop_setCiphers ciphers cp = ciphers == (TLS.supportedCiphers $ clientSupported $ setCiphers ciphers cp)

prop_setCA :: ClientParams -> Bool
prop_setCA cp = [] == (listCertificates $ TLS.sharedCAStore $ clientShared $ setCA (makeCertificateStore []) cp)

prop_setServerValidator :: PropertyM IO ()
prop_setServerValidator = do
  exp_reasons <- pick $ arbitrary
  cp <- pick $ arbitrary
  let input_validator = \_ _ _ _ -> return exp_reasons
      got_validator = (TLS.onServerCertificate $ clientHooks $ setServerValidator input_validator cp)
  got_reasons <- run $ got_validator mempty def (mempty, mempty) (CertificateChain [])
  assert (got_reasons == exp_reasons)
