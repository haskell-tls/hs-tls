{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module Network.TLS.ECH.Config where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as C8
import Data.Word
import Network.ByteOrder
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

class SizeOf a where
    sizeof :: a -> Int

----------------------------------------------------------------

data HpkeSymmetricCipherSuite = HpkeSymmetricCipherSuite
    { kdf_id :: Word16
    , aead_id :: Word16
    }
    deriving (Eq, Ord)

instance SizeOf HpkeSymmetricCipherSuite where
    sizeof _ = 4

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

getHpkeSymmetricCipherSuite :: ReadBuffer -> IO HpkeSymmetricCipherSuite
getHpkeSymmetricCipherSuite rbuf =
    HpkeSymmetricCipherSuite <$> read16 rbuf <*> read16 rbuf

putHpkeSymmetricCipherSuite :: WriteBuffer -> HpkeSymmetricCipherSuite -> IO ()
putHpkeSymmetricCipherSuite wbuf HpkeSymmetricCipherSuite{..} = do
    write16 wbuf kdf_id
    write16 wbuf aead_id

----------------------------------------------------------------

newtype EncodedPublicKey = EncodedPublicKey ByteString deriving (Eq, Ord)
instance Show EncodedPublicKey where
    show (EncodedPublicKey bs) = "\"" ++ C8.unpack (B16.encode bs) ++ "\""

instance SizeOf EncodedPublicKey where
    sizeof (EncodedPublicKey bs) = 2 + BS.length bs

data HpkeKeyConfig = HpkeKeyConfig
    { config_id :: Word8
    , kem_id :: Word16
    , public_key :: EncodedPublicKey
    , cipher_suites :: [HpkeSymmetricCipherSuite]
    }
    deriving (Eq, Ord)

instance SizeOf HpkeKeyConfig where
    sizeof HpkeKeyConfig{..} = 5 + sizeof public_key + sum (map sizeof cipher_suites)

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

getHpkeKeyConfig :: ReadBuffer -> IO HpkeKeyConfig
getHpkeKeyConfig rbuf = do
    cfid <- read8 rbuf
    kid <- read16 rbuf
    pk <- EncodedPublicKey <$> getOpaque16 rbuf
    cs <- getList16 rbuf getHpkeSymmetricCipherSuite
    return $ HpkeKeyConfig cfid kid pk cs

putHpkeKeyConfig :: WriteBuffer -> HpkeKeyConfig -> IO ()
putHpkeKeyConfig wbuf HpkeKeyConfig{..} = do
    write8 wbuf config_id
    write16 wbuf kem_id
    let EncodedPublicKey pk = public_key
    putOpaque16 wbuf pk
    putList16 wbuf putHpkeSymmetricCipherSuite cipher_suites

----------------------------------------------------------------

type ECHConfigExtensionType = Word16

data ECHConfigExtension = ECHConfigExtension
    { ece_type :: ECHConfigExtensionType
    , ece_data :: ByteString
    }
    deriving (Eq, Ord, Show)

instance SizeOf ECHConfigExtension where
    sizeof ECHConfigExtension{..} = 4 + BS.length ece_data

getECHConfigExtension :: ReadBuffer -> IO ECHConfigExtension
getECHConfigExtension rbuf = do
    typ <- read16 rbuf
    ext <- getOpaque16 rbuf
    return $ ECHConfigExtension typ ext

putECHConfigExtension :: WriteBuffer -> ECHConfigExtension -> IO ()
putECHConfigExtension wbuf ECHConfigExtension{..} = do
    write16 wbuf ece_type
    putOpaque16 wbuf ece_data

----------------------------------------------------------------

data ECHConfigContents = ECHConfigContents
    { key_config :: HpkeKeyConfig
    , maximum_name_length :: Word8
    , public_name :: ByteString
    , extensions :: [ECHConfigExtension]
    }
    deriving (Eq, Ord, Show)

instance SizeOf ECHConfigContents where
    sizeof ECHConfigContents{..} = sizeof key_config + 4 + BS.length public_name + sum (map sizeof extensions)

getECHConfigContents :: ReadBuffer -> IO ECHConfigContents
getECHConfigContents rbuf = do
    kcf <- getHpkeKeyConfig rbuf
    mnl <- read8 rbuf
    pn <- getOpaque8 rbuf
    exts <- getList16 rbuf getECHConfigExtension
    return $ ECHConfigContents kcf mnl pn exts

putECHConfigContents :: WriteBuffer -> ECHConfigContents -> IO ()
putECHConfigContents wbuf ECHConfigContents{..} = do
    putHpkeKeyConfig wbuf key_config
    write8 wbuf maximum_name_length
    putOpaque8 wbuf public_name
    putList16 wbuf putECHConfigExtension extensions

----------------------------------------------------------------

data ECHConfig = ECHConfig
    { contents :: ECHConfigContents
    }
    deriving (Eq, Ord)

instance SizeOf ECHConfig where
    sizeof ECHConfig{..} = 4 + sizeof contents

instance Show ECHConfig where
    show ECHConfig{..} = show contents

getECHConfig :: ReadBuffer -> IO ECHConfig
getECHConfig rbuf = do
    _ver <- read16 rbuf
    _len <- read16 rbuf
    ECHConfig <$> getECHConfigContents rbuf

putECHConfig :: WriteBuffer -> ECHConfig -> IO ()
putECHConfig wbuf ECHConfig{..} = do
    write16 wbuf 0xfe0d
    withLength16 wbuf $ putECHConfigContents wbuf contents

----------------------------------------------------------------

getOpaque8 :: ReadBuffer -> IO ByteString
getOpaque8 rbuf = do
    len <- fromIntegral <$> read8 rbuf
    extractByteString rbuf len

putOpaque8 :: WriteBuffer -> ByteString -> IO ()
putOpaque8 wbuf x = do
    write8 wbuf $ fromIntegral $ BS.length x
    copyByteString wbuf x

getOpaque16 :: ReadBuffer -> IO ByteString
getOpaque16 rbuf = do
    len <- fromIntegral <$> read16 rbuf
    extractByteString rbuf len

putOpaque16 :: WriteBuffer -> ByteString -> IO ()
putOpaque16 wbuf x = do
    write16 wbuf $ fromIntegral $ BS.length x
    copyByteString wbuf x

getList16 :: ReadBuffer -> (ReadBuffer -> IO a) -> IO [a]
getList16 rbuf parer = do
    len <- fromIntegral <$> read16 rbuf
    cur <- position rbuf
    let lim = cur + len
    loop lim id
  where
    loop lim build = do
        cur <- position rbuf
        if cur < lim
            then do
                x <- parer rbuf
                loop lim ((x :) . build)
            else return $ build []

withLength16 :: WriteBuffer -> IO () -> IO ()
withLength16 wbuf builder = do
    lenpos <- position wbuf
    write16 wbuf 0
    old <- position wbuf
    builder
    new <- position wbuf
    let len = new - old
    ff wbuf (lenpos - new)
    write16 wbuf $ fromIntegral len
    ff wbuf len

putList16 :: WriteBuffer -> (WriteBuffer -> a -> IO ()) -> [a] -> IO ()
putList16 wbuf builder xxs =
    withLength16 wbuf $ loop xxs
  where
    loop [] = return ()
    loop (x : xs) = do
        builder wbuf x
        loop xs
