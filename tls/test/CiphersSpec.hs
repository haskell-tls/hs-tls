module CiphersSpec where

import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Network.TLS.Cipher
import Network.TLS.Extra.Cipher
import Network.TLS.Internal (paddingIsValid)
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

spec :: Spec
spec = do
    describe "ciphers" $ do
        prop "can ecnrypt/decrypt" $ \(BulkTest bulk key iv t additional) -> do
            let enc = bulkInit bulk BulkEncrypt key
                dec = bulkInit bulk BulkDecrypt key
            case (enc, dec) of
                (BulkStateBlock encF, BulkStateBlock decF) -> block encF decF iv t
                (BulkStateAEAD encF, BulkStateAEAD decF) -> aead encF decF iv t additional
                (BulkStateStream (BulkStream encF), BulkStateStream (BulkStream decF)) -> stream encF decF t
                _ -> return ()
    describe "CBC padding" $ do
        -- Read in constant time; the answer is still the plain one.
        prop "is valid when the last octets equal the last" $ \(NonEmpty ws) (Positive n) -> do
            let plain = B.pack ws
                padLen = 1 + (n - 1) `mod` min 256 (B.length plain)
                expected = B.all (== B.last plain) $ B.drop (B.length plain - padLen) plain
            paddingIsValid plain padLen `shouldBe` expected
        prop "accepts a padding filled with its length" $ \ws (Positive n) -> do
            let len = (n - 1) `mod` 256
                plain = B.pack ws <> B.replicate (len + 1) (fromIntegral len)
            paddingIsValid plain (len + 1) `shouldBe` True

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

arbitraryKey :: Bulk -> Gen BA.ScrubbedBytes
arbitraryKey bulk = BA.pack `fmap` vector (bulkKeySize bulk)

arbitraryIV :: Bulk -> Gen B.ByteString
arbitraryIV bulk = B.pack `fmap` vector (bulkIVSize bulk + bulkExplicitIV bulk)

arbitraryText :: Bulk -> Gen B.ByteString
arbitraryText bulk = B.pack `fmap` vector (bulkBlockSize bulk)

data BulkTest
    = BulkTest Bulk BA.ScrubbedBytes B.ByteString B.ByteString B.ByteString
    deriving (Show, Eq)

instance Arbitrary BulkTest where
    arbitrary = do
        bulk <- cipherBulk `fmap` elements ciphersuite_all
        BulkTest bulk
            <$> arbitraryKey bulk
            <*> arbitraryIV bulk
            <*> arbitraryText bulk
            <*> arbitraryText bulk
