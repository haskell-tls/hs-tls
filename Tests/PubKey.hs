module Tests.PubKey
	( arbitraryRSAPair
	, globalRSAPair
	, getGlobalRSAPair
	) where

import Test.QuickCheck

import qualified Crypto.Random.AESCtr as RNG
import qualified Crypto.Cipher.RSA as RSA

import qualified Data.ByteString as B

import Control.Concurrent.MVar
import System.IO.Unsafe

arbitraryRSAPair :: Gen (RSA.PublicKey, RSA.PrivateKey)
arbitraryRSAPair = do
	rng <- (either (error . show) id . RNG.make . B.pack) `fmap` vector 64
	arbitraryRSAPairWithRNG rng

arbitraryRSAPairWithRNG rng = case RSA.generate rng 128 65537 of
	Left _             -> error "couldn't generate RSA"
	Right (keypair, _) -> return keypair

{-# NOINLINE globalRSAPair #-}
globalRSAPair :: MVar (RSA.PublicKey, RSA.PrivateKey)
globalRSAPair = unsafePerformIO (RNG.makeSystem >>= arbitraryRSAPairWithRNG >>= newMVar)

{-# NOINLINE getGlobalRSAPair #-}
getGlobalRSAPair :: (RSA.PublicKey, RSA.PrivateKey)
getGlobalRSAPair = unsafePerformIO (readMVar globalRSAPair)
