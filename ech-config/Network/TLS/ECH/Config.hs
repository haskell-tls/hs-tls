{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.TLS.ECH.Config where

import Data.ByteString
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as C8
import Data.Word
import Text.Printf (printf)

{-
fe0d version
0041 length
18 config_id
0020 DHKEM(X25519, HKDF-SHA256) table 2
0020 len
d5a7cb30a0cf844548a33bdcdebfe9bc
f1ef67912704bf9dcab026d8f292cb15 public_key
0004 len
0001 HKDF-SHA256 table 4
0001 AES-128-GCM table 5
0012 len
636c6f7564666c6172652d6563682e636f6d .com
0000 len
-}

example0 :: ByteString
example0 =
    "\xfe\x0d\x00\x41\x18\x00\x20\x00\x20\xd5\xa7\xcb\x30\xa0\xcf\x84\x45\x48\xa3\x3b\xdc\xde\xbf\xe9\xbc\xf1\xef\x67\x91\x27\x04\xbf\x9d\xca\xb0\x26\xd8\xf2\x92\xcb\x15\x00\x04\x00\x01\x00\x01\x00\x12\x63\x6c\x6f\x75\x64\x66\x6c\x61\x72\x65\x2d\x65\x63\x68\x2e\x63\x6f\x6d\x00\x00"

example1 :: ByteString
example1 =
    "\xfe\x0d\x00\x41\x18\x00\x20\x00\x20\xd5\xa7\xcb\x30\xa0\xcf\x84\x45\x48\xa3\x3b\xdc\xde\xbf\xe9\xbc\xf1\xef\x67\x91\x27\x04\xbf\x9d\xca\xb0\x26\xd8\xf2\x92\xcb\x15\x00\x04\x00\x01\x00\x01\x00\x12\x63\x6c\x6f\x75\x64\x66\x6c\x61\x72\x65\x2d\x65\x63\x68\x2e\x63\x6f\x6d\x00\x00"

----------------------------------------------------------------

data HpkeSymmetricCipherSuite = HpkeSymmetricCipherSuite
    { kdf_id :: Word16
    , aead_id :: Word16
    }
    deriving (Eq, Ord)

instance Show HpkeSymmetricCipherSuite where
    show HpkeSymmetricCipherSuite{..} = "(" ++ showKDF_ID kdf_id ++ "," ++ showAEAD_ID aead_id ++ ")"
      where
        showKDF_ID 0x0000 = "KDF-Reserved"
        showKDF_ID 0x0001 = "HKDF-SHA256"
        showKDF_ID 0x0002 = "HKDF-SHA384"
        showKDF_ID 0x0003 = "HKDF-SHA512"
        showKDF_ID x = "KDF_ID " ++ printf "0x04" x
        showAEAD_ID 0x000 = "AEAD_Reserved"
        showAEAD_ID 0x001 = "AES-128-GCM"
        showAEAD_ID 0x002 = "AES-256-GCM"
        showAEAD_ID 0x003 = "ChaCha20Poly1305"
        showAEAD_ID 0xFFF = "Export-only"
        showAEAD_ID x = "AEAD_ID " ++ printf "0x04" x

----------------------------------------------------------------

newtype EncodedPublicKey = PublicKey ByteString deriving (Eq, Ord)
instance Show EncodedPublicKey where
    show (PublicKey bs) = "\"" ++ C8.unpack (B16.encode bs) ++ "\""

data HpkeKeyConfig = HpkeKeyConfig
    { config_id :: Word8
    , kem_id :: Word16
    , public_key :: EncodedPublicKey
    , cipher_suites :: [HpkeSymmetricCipherSuite]
    }
    deriving (Eq, Ord)

instance Show HpkeKeyConfig where
    show HpkeKeyConfig{..} =
        "{"
            ++ show config_id
            ++ ", "
            ++ showKEM_ID kem_id
            ++ ", "
            ++ show public_key
            ++ ", "
            ++ show cipher_suites
            ++ "}"
      where
        showKEM_ID 0x0000 = "KEM_Reserved"
        showKEM_ID 0x0010 = "DHKEM(P-256, HKDF-SHA256)"
        showKEM_ID 0x0011 = "DHKEM(P-384, HKDF-SHA384)"
        showKEM_ID 0x0012 = "DHKEM(P-521, HKDF-SHA512)"
        showKEM_ID 0x0020 = "DHKEM(X25519, HKDF-SHA256)"
        showKEM_ID 0x0021 = "DHKEM(X448, HKDF-SHA512)"
        showKEM_ID x = "KEM_ID " ++ printf "0x04" x

----------------------------------------------------------------

type ECHConfigExtensionType = Word16

data ECHConfigExtension = ECHConfigExtension
    { ece_type :: ECHConfigExtensionType
    , ece_data :: ByteString
    }
    deriving (Eq, Ord, Show)

----------------------------------------------------------------

data ECHConfigContents = ECHConfigContents
    { key_config :: HpkeKeyConfig
    , maximum_name_length :: Word8
    , public_name :: ByteString
    , extensions :: [ECHConfigExtension]
    }
    deriving (Eq, Ord, Show)

----------------------------------------------------------------

data ECHConfig = ECHConfig
    { contents :: ECHConfigContents
    }
    deriving (Eq, Ord)

instance Show ECHConfig where
    show ECHConfig{..} = show contents
