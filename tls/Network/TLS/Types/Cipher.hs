{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE PatternSynonyms #-}

module Network.TLS.Types.Cipher where

import Codec.Serialise
import Crypto.Cipher.Types (AuthTag)
import Data.IORef
import GHC.Generics
import System.IO.Unsafe (unsafePerformIO)
import Text.Printf

import Network.TLS.Crypto (Hash (..))
import Network.TLS.Imports
import Network.TLS.Types.Version

----------------------------------------------------------------

-- | Cipher identification
newtype CipherID = CipherID {getCipherID :: Word16} deriving (Eq, Generic)

instance Show CipherID where
    show (CipherID 0x00FF) = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
    show (CipherID n) = case find eqID dict of
        Just c -> cipherName c
        Nothing -> printf "0x%04X" n
      where
        eqID c = cipherID c == CipherID n
        dict = unsafePerformIO $ readIORef globalCipherDict

-- "ciphersuite" is designed extensible.
-- So, it's not available from internal modules.
-- This is a compromise to gule "ciphersuite" to Show CipherID.

{-# NOINLINE globalCipherDict #-}
globalCipherDict :: IORef [Cipher]
globalCipherDict = unsafePerformIO $ newIORef []

----------------------------------------------------------------

-- | Cipher algorithm
data Cipher = Cipher
    { cipherID :: CipherID
    , cipherName :: String
    , cipherHash :: Hash
    , cipherBulk :: Bulk
    , cipherKeyExchange :: CipherKeyExchangeType
    , cipherMinVer :: Maybe Version
    , cipherPRFHash :: Maybe Hash
    }

instance Show Cipher where
    show c = cipherName c

instance Eq Cipher where
    (==) c1 c2 = cipherID c1 == cipherID c2

----------------------------------------------------------------

data CipherKeyExchangeType
    = CipherKeyExchange_RSA
    | CipherKeyExchange_DH_Anon
    | CipherKeyExchange_DHE_RSA
    | CipherKeyExchange_ECDHE_RSA
    | CipherKeyExchange_DHE_DSA
    | CipherKeyExchange_DH_DSA
    | CipherKeyExchange_DH_RSA
    | CipherKeyExchange_ECDH_ECDSA
    | CipherKeyExchange_ECDH_RSA
    | CipherKeyExchange_ECDHE_ECDSA
    | CipherKeyExchange_TLS13 -- not expressed in cipher suite
    deriving (Show, Eq)

----------------------------------------------------------------

data Bulk = Bulk
    { bulkName :: String
    , bulkKeySize :: Int
    , bulkIVSize :: Int
    , bulkExplicitIV :: Int -- Explicit size for IV for AEAD Cipher, 0 otherwise
    , bulkAuthTagLen :: Int -- Authentication tag length in bytes for AEAD Cipher, 0 otherwise
    , bulkBlockSize :: Int
    , bulkF :: BulkFunctions
    }

instance Show Bulk where
    show bulk = bulkName bulk
instance Eq Bulk where
    b1 == b2 =
        and
            [ bulkName b1 == bulkName b2
            , bulkKeySize b1 == bulkKeySize b2
            , bulkIVSize b1 == bulkIVSize b2
            , bulkBlockSize b1 == bulkBlockSize b2
            ]

----------------------------------------------------------------

data BulkFunctions
    = BulkBlockF (BulkDirection -> BulkKey -> BulkBlock)
    | BulkStreamF (BulkDirection -> BulkKey -> BulkStream)
    | BulkAeadF (BulkDirection -> BulkKey -> BulkAEAD)

data BulkDirection = BulkEncrypt | BulkDecrypt
    deriving (Show, Eq)

type BulkBlock = BulkIV -> ByteString -> (ByteString, BulkIV)

type BulkKey = ByteString
type BulkIV = ByteString
type BulkNonce = ByteString
type BulkAdditionalData = ByteString

newtype BulkStream = BulkStream (ByteString -> (ByteString, BulkStream))

type BulkAEAD =
    BulkNonce -> ByteString -> BulkAdditionalData -> (ByteString, AuthTag)

instance Serialise CipherID
