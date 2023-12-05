module CiphersSpec where

import Test.Hspec
import Test.QuickCheck

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Network.TLS.Cipher
import Network.TLS.Extra.Cipher

spec :: Spec
spec = do
    describe "ciphers" $ do
        it "can ecnrypt/decrypt" $ property $ \(BulkTest bulk key iv t additional) -> do
            let enc = bulkInit bulk BulkEncrypt key
                dec = bulkInit bulk BulkDecrypt key
            case (enc, dec) of
                (BulkStateBlock encF, BulkStateBlock decF) -> block encF decF iv t
                (BulkStateAEAD encF, BulkStateAEAD decF) -> aead encF decF iv t additional
                (BulkStateStream (BulkStream encF), BulkStateStream (BulkStream decF)) -> stream encF decF t
                _ -> return ()

block
    :: BulkBlock
    -> BulkBlock
    -> BulkIV
    -> ByteString
    -> IO ()
block e d iv t = do
    let (etxt, e_iv) = e iv t
        (dtxt, d_iv) = d iv etxt
    dtxt `shouldBe` t
    d_iv `shouldBe` e_iv

stream
    :: (ByteString -> (ByteString, BulkStream))
    -> (ByteString -> (ByteString, BulkStream))
    -> ByteString
    -> Expectation
stream e d t = (fst . d . fst . e) t `shouldBe` t

aead
    :: BulkAEAD
    -> BulkAEAD
    -> BulkNonce
    -> ByteString
    -> BulkAdditionalData
    -> Expectation
aead e d iv t additional = do
    let (encrypted, at) = e iv t additional
        (decrypted, at2) = d iv encrypted additional
    decrypted `shouldBe` t
    at `shouldBe` at2

arbitraryKey :: Bulk -> Gen B.ByteString
arbitraryKey bulk = B.pack `fmap` vector (bulkKeySize bulk)

arbitraryIV :: Bulk -> Gen B.ByteString
arbitraryIV bulk = B.pack `fmap` vector (bulkIVSize bulk + bulkExplicitIV bulk)

arbitraryText :: Bulk -> Gen B.ByteString
arbitraryText bulk = B.pack `fmap` vector (bulkBlockSize bulk)

data BulkTest = BulkTest Bulk B.ByteString B.ByteString B.ByteString B.ByteString
    deriving (Show, Eq)

instance Arbitrary BulkTest where
    arbitrary = do
        bulk <- cipherBulk `fmap` elements ciphersuite_all
        BulkTest bulk
            <$> arbitraryKey bulk
            <*> arbitraryIV bulk
            <*> arbitraryText bulk
            <*> arbitraryText bulk
