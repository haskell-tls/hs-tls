-- Disable this warning so we can still test deprecated functionality.
{-# OPTIONS_GHC -fno-warn-warnings-deprecations #-}
module Ciphers
    ( propertyBulkFunctional
    ) where

import Control.Applicative ((<$>), (<*>))

import Test.Tasty.QuickCheck

import qualified Data.ByteString as B
import Network.TLS.Cipher
import Network.TLS.Extra.Cipher

arbitraryKey :: Bulk -> Gen B.ByteString
arbitraryKey bulk = B.pack `fmap` vector (bulkKeySize bulk)

arbitraryIV :: Bulk -> Gen B.ByteString
arbitraryIV bulk = B.pack `fmap` vector (bulkIVSize bulk + bulkExplicitIV bulk)

arbitraryText :: Bulk -> Gen B.ByteString
arbitraryText bulk = B.pack `fmap` vector (bulkBlockSize bulk)

data BulkTest = BulkTest Bulk B.ByteString B.ByteString B.ByteString B.ByteString
    deriving (Show,Eq)

instance Arbitrary BulkTest where
    arbitrary = do
        bulk <- cipherBulk `fmap` elements ciphersuite_all
        BulkTest bulk <$> arbitraryKey bulk <*> arbitraryIV bulk <*> arbitraryText bulk <*> arbitraryText bulk

propertyBulkFunctional :: BulkTest -> Bool
propertyBulkFunctional (BulkTest bulk key iv t additional) =
    let enc = bulkInit bulk BulkEncrypt key
        dec = bulkInit bulk BulkDecrypt key
     in case (enc, dec) of
        (BulkStateBlock encF, BulkStateBlock decF)   -> block encF decF
        (BulkStateAEAD encF, BulkStateAEAD decF)     -> aead encF decF
        (BulkStateStream (BulkStream encF), BulkStateStream (BulkStream decF)) -> stream encF decF
        _                                            -> True
  where
        block e d =
            let (etxt, e_iv) = e iv t
                (dtxt, d_iv) = d iv etxt
             in dtxt == t && d_iv == e_iv
        stream e d = (fst . d . fst . e) t == t
        aead e d =
            let (encrypted, at)  = e iv t additional
                (decrypted, at2) = d iv encrypted additional
             in decrypted == t && at == at2
