module Tests.Ciphers
	( runTests
	) where

import Data.Word
import Control.Applicative ((<$>))

import Tests.Common
import Test.QuickCheck

import qualified Data.ByteString as B
import Network.TLS.Cipher

arbitraryKey :: Cipher -> Gen [Word8]
arbitraryKey cipher = vector (fromIntegral $ cipherKeySize cipher)

arbitraryIV :: Cipher -> Gen [Word8]
arbitraryIV cipher = vector (fromIntegral $ cipherIVSize cipher)

arbitraryText :: Cipher -> Gen [Word8]
arbitraryText cipher = vector (fromIntegral $ cipherPaddingSize cipher)

cipher_test cipher = run_test n t
	where
		n = ("cipher: " ++ cipherName cipher ++ ": decrypt . encrypt = id")
		t = case cipherF cipher of
			CipherBlockF enc dec       -> do
				key <- B.pack <$> arbitraryKey cipher
				iv  <- B.pack <$> arbitraryIV cipher
				t   <- B.pack <$> arbitraryText cipher
				return $ block enc dec key iv t
			CipherStreamF ktoi enc dec -> do
				key <- B.pack <$> arbitraryKey cipher
				t   <- B.pack <$> arbitraryText cipher
				return $ stream ktoi enc dec key t
		block e d key iv t = (d key iv . e key iv) t == t
		stream ktoi e d key t = (fst . d iv . fst . e iv) t == t
			where iv = ktoi key

runTests = mapM_ cipher_test supportedCiphers
