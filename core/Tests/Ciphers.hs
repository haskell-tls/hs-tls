module Ciphers
    ( propertyBulkFunctional
    ) where

import Control.Applicative ((<$>), (<*>))

import Test.QuickCheck

import qualified Data.ByteString as B
import Network.TLS.Cipher
import Network.TLS.Extra.Cipher

arbitraryKey :: Bulk -> Gen B.ByteString
arbitraryKey bulk = B.pack `fmap` vector (fromIntegral $ bulkKeySize bulk)

arbitraryIV :: Bulk -> Gen B.ByteString
arbitraryIV bulk = B.pack `fmap` vector (fromIntegral $ bulkIVSize bulk)

arbitraryText :: Bulk -> Gen B.ByteString
arbitraryText bulk = B.pack `fmap` vector (fromIntegral $ bulkBlockSize bulk)

data BulkTest = BulkTest Bulk B.ByteString B.ByteString B.ByteString
    deriving (Show,Eq)

instance Arbitrary BulkTest where
    arbitrary = do
        bulk <- cipherBulk `fmap` elements ciphersuite_all
        BulkTest bulk <$> arbitraryKey bulk <*> arbitraryIV bulk <*> arbitraryText bulk

propertyBulkFunctional :: BulkTest -> Bool
propertyBulkFunctional (BulkTest bulk key iv t) =
    case bulkF bulk of
        BulkBlockF enc dec       -> block enc dec
        BulkStreamF ktoi enc dec -> stream ktoi enc dec
  where
        block e d = (d key iv . e key iv) t == t
        stream ktoi e d = (fst . d siv . fst . e siv) t == t
            where siv = ktoi key
