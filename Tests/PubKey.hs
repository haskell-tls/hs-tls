module Tests.PubKey
	( arbitraryRSAPair
	) where

import Test.QuickCheck

import qualified Crypto.Random.AESCtr as RNG
import qualified Crypto.Cipher.RSA as RSA

import qualified Data.ByteString as B

arbitraryRSAPair :: Gen (RSA.PublicKey, RSA.PrivateKey)
arbitraryRSAPair = do
	rng <- (either (error . show) id . RNG.make . B.pack) `fmap` vector 64
	case RSA.generate rng 128 65537 of
		Left _             -> error "couldn't generate RSA"
		Right (keypair, _) -> return keypair
