{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.TLS.ECH.Config where

import Data.ByteString
import Data.Word

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

example :: ByteString
example =
    "\xfe\x0d\x00\x41\x18\x00\x20\x00\x20\xd5\xa7\xcb\x30\xa0\xcf\x84\x45\x48\xa3\x3b\xdc\xde\xbf\xe9\xbc\xf1\xef\x67\x91\x27\x04\xbf\x9d\xca\xb0\x26\xd8\xf2\x92\xcb\x15\x00\x04\x00\x01\x00\x01\x00\x12\x63\x6c\x6f\x75\x64\x66\x6c\x61\x72\x65\x2d\x65\x63\x68\x2e\x63\x6f\x6d\x00\x00"

data HpkeSymmetricCipherSuite = HpkeSymmetricCipherSuite
    { kdf_id :: Word8
    , aead_id :: Word8
    }
    deriving (Eq)

instance Show HpkeSymmetricCipherSuite where
    show HpkeSymmetricCipherSuite{..} = "(" ++ show kdf_id ++ "," ++ show aead_id ++ ")"

data HpkeKeyConfig = HpkeKeyConfig
    { config_id :: Word8
    , kem_id :: Word8
    , public_key :: ByteString
    , cipher_suites :: [HpkeSymmetricCipherSuite]
    }
    deriving (Eq, Show)

type ECHConfigExtensionType = Word16

data ECHConfigExtension = ECHConfigExtension
    { ece_type :: ECHConfigExtensionType
    , ece_data :: ByteString
    }
    deriving (Eq, Show)

data ECHConfigContents = ECHConfigContents
    { key_config :: HpkeKeyConfig
    , public_name :: ByteString
    , extensions :: [ECHConfigExtension]
    }
    deriving (Eq, Show)

data ECHConfig = ECHConfig
    { version :: Word16
    , contents :: ECHConfigContents
    }
    deriving (Eq)

instance Show ECHConfig where
    show ECHConfig{..} = show contents
