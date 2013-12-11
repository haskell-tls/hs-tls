module PubKey
    ( arbitraryRSAPair
    , globalRSAPair
    , getGlobalRSAPair
    , dhParams
    ) where

import Test.QuickCheck

import qualified Crypto.PubKey.DH as DH
import Crypto.Random (createTestEntropyPool)
import qualified Crypto.Random.AESCtr as RNG
import qualified Crypto.PubKey.RSA as RSA

import qualified Data.ByteString as B

import Control.Concurrent.MVar
import System.IO.Unsafe

arbitraryRSAPair :: Gen (RSA.PublicKey, RSA.PrivateKey)
arbitraryRSAPair = do
    rng <- (RNG.make . createTestEntropyPool . B.pack) `fmap` vector 64
    arbitraryRSAPairWithRNG rng

arbitraryRSAPairWithRNG rng = return $ fst $ RSA.generate rng 128 0x10001

{-# NOINLINE globalRSAPair #-}
globalRSAPair :: MVar (RSA.PublicKey, RSA.PrivateKey)
globalRSAPair = unsafePerformIO (RNG.makeSystem >>= arbitraryRSAPairWithRNG >>= newMVar)

{-# NOINLINE getGlobalRSAPair #-}
getGlobalRSAPair :: (RSA.PublicKey, RSA.PrivateKey)
getGlobalRSAPair = unsafePerformIO (readMVar globalRSAPair)

dhParams :: DH.Params
dhParams = DH.Params
    { DH.params_p = 0x00ccaa3884b50789ebea8d39bef8bbc66e20f2a78f537a76f26b4edde5de8b0ff15a8193abf0873cbdc701323a2bf6e860affa6e043fe8300d47e95baf9f6354cb
    , DH.params_g = 0x2
    }
