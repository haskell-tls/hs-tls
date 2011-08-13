module Tests.Ciphers
	( runTests
	) where

import Data.Word
import Control.Applicative ((<$>))

import Tests.Common
import Test.QuickCheck

import qualified Data.ByteString as B
import Network.TLS.Cipher

arbitraryKey :: Bulk -> Gen [Word8]
arbitraryKey bulk = vector (fromIntegral $ bulkKeySize bulk)

arbitraryIV :: Bulk -> Gen [Word8]
arbitraryIV bulk = vector (fromIntegral $ bulkIVSize bulk)

arbitraryText :: Bulk -> Gen [Word8]
arbitraryText bulk = vector (fromIntegral $ bulkBlockSize bulk)

bulk_test bulk = run_test n t
	where
		n = ("bulk: " ++ bulkName bulk ++ ": decrypt . encrypt = id")
		t = case bulkF bulk of
			BulkBlockF enc dec       -> do
				key <- B.pack <$> arbitraryKey bulk
				iv  <- B.pack <$> arbitraryIV bulk
				t   <- B.pack <$> arbitraryText bulk
				return $ block enc dec key iv t
			BulkStreamF ktoi enc dec -> do
				key <- B.pack <$> arbitraryKey bulk
				t   <- B.pack <$> arbitraryText bulk
				return $ stream ktoi enc dec key t
			BulkNoneF -> do
				return True
		block e d key iv t = (d key iv . e key iv) t == t
		stream ktoi e d key t = (fst . d iv . fst . e iv) t == t
			where iv = ktoi key

runTests = mapM_ (bulk_test . cipherBulk) supportedCiphers
