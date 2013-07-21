module PubKey
    ( arbitraryRSAPair
    , globalRSAPair
    , getGlobalRSAPair
    ) where

import Test.QuickCheck

import qualified Crypto.Random.AESCtr as RNG
import qualified Crypto.PubKey.RSA as RSA

import qualified Data.ByteString as B

import Control.Concurrent.MVar
import System.IO.Unsafe

arbitraryRSAPair :: Gen (RSA.PublicKey, RSA.PrivateKey)
arbitraryRSAPair = do
    rng <- (maybe (error "making rng") id . RNG.make . B.pack) `fmap` vector 64
    arbitraryRSAPairWithRNG rng

arbitraryRSAPairWithRNG rng = return $ fst $ RSA.generate rng 128 0x10001

{-# NOINLINE globalRSAPair #-}
globalRSAPair :: MVar (RSA.PublicKey, RSA.PrivateKey)
globalRSAPair = unsafePerformIO (RNG.makeSystem >>= arbitraryRSAPairWithRNG >>= newMVar)

{-# NOINLINE getGlobalRSAPair #-}
getGlobalRSAPair :: (RSA.PublicKey, RSA.PrivateKey)
getGlobalRSAPair = unsafePerformIO (readMVar globalRSAPair)
