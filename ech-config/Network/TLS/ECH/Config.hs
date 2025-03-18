{-# LANGUAGE RecordWildCards #-}

-- | Types for Configuration of Encrypted Client Hello.
module Network.TLS.ECH.Config (
    -- * Types
    ECHConfigList,
    ECHConfig (..),
    ECHConfigContents (..),
    HpkeKeyConfig (..),
    ConfigId,
    EncodedServerPublicKey (..),
    HpkeSymmetricCipherSuite (..),
    ECHConfigExtensionType,
    ECHConfigExtension (..),

    -- * ECH configuration list
    decodeECHConfigList,
    encodeECHConfigList,
    loadECHConfigList,
    loadECHSecretKeys,

    -- * ECH configuration
    decodeECHConfig,
    encodeECHConfig,

    -- * Low level
    getECHConfigList,
    putECHConfigList,
    sizeOfECHConfigList,
    getECHConfig,
    putECHConfig,
    sizeOfECHConfig,
) where

import qualified Control.Exception as E
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as C8
import Data.Char (isDigit)
import Data.Word
import Network.ByteOrder
import System.FilePath (takeFileName)
import System.IO.Unsafe (unsafePerformIO)
import Text.Printf (printf)

----------------------------------------------------------------

class SizeOf a where
    sizeof :: a -> Int

----------------------------------------------------------------

-- | Type for cipher suite.
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
        showAEAD_ID 0x0000 = "AEAD_Reserved"
        showAEAD_ID 0x0001 = "AES-128-GCM"
        showAEAD_ID 0x0002 = "AES-256-GCM"
        showAEAD_ID 0x0003 = "ChaCha20Poly1305"
        showAEAD_ID 0xFFFF = "Export-only"
        showAEAD_ID x = "AEAD_ID " ++ printf "0x04" x

getHpkeSymmetricCipherSuite :: ReadBuffer -> IO HpkeSymmetricCipherSuite
getHpkeSymmetricCipherSuite rbuf =
    HpkeSymmetricCipherSuite <$> read16 rbuf <*> read16 rbuf

putHpkeSymmetricCipherSuite :: WriteBuffer -> HpkeSymmetricCipherSuite -> IO ()
putHpkeSymmetricCipherSuite wbuf HpkeSymmetricCipherSuite{..} = do
    write16 wbuf kdf_id
    write16 wbuf aead_id

----------------------------------------------------------------

-- | Encoded public key.
newtype EncodedServerPublicKey = EncodedServerPublicKey ByteString
    deriving (Eq, Ord)

instance Show EncodedServerPublicKey where
    show (EncodedServerPublicKey bs) = "\"" ++ C8.unpack (B16.encode bs) ++ "\""

instance SizeOf EncodedServerPublicKey where
    sizeof (EncodedServerPublicKey bs) = 2 + BS.length bs

-- | Configuration identifier.
type ConfigId = Word8

-- | Key configuration.
data HpkeKeyConfig = HpkeKeyConfig
    { config_id :: ConfigId
    , kem_id :: Word16
    , public_key :: EncodedServerPublicKey
    , cipher_suites :: [HpkeSymmetricCipherSuite]
    }
    deriving (Eq, Ord)

instance SizeOf HpkeKeyConfig where
    sizeof HpkeKeyConfig{..} = 5 + sizeof public_key + sum (map sizeof cipher_suites)

instance Show HpkeKeyConfig where
    show HpkeKeyConfig{..} =
        "("
            ++ show config_id
            ++ ", "
            ++ showKEM_ID kem_id
            ++ ", "
            ++ show public_key
            ++ ", "
            ++ show cipher_suites
            ++ ")"
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
    pk <- EncodedServerPublicKey <$> getOpaque16 rbuf
    cs <- getList16 rbuf getHpkeSymmetricCipherSuite
    return $ HpkeKeyConfig cfid kid pk cs

putHpkeKeyConfig :: WriteBuffer -> HpkeKeyConfig -> IO ()
putHpkeKeyConfig wbuf HpkeKeyConfig{..} = do
    write8 wbuf config_id
    write16 wbuf kem_id
    let EncodedServerPublicKey pk = public_key
    putOpaque16 wbuf pk
    putList16 wbuf putHpkeSymmetricCipherSuite cipher_suites

----------------------------------------------------------------

-- | Extension type.
type ECHConfigExtensionType = Word16

-- | Raw extension.
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
    , public_name :: String
    , extensions :: [ECHConfigExtension]
    }
    deriving (Eq, Ord)

instance Show ECHConfigContents where
    show ECHConfigContents{..} =
        init (show key_config)
            ++ ", "
            ++ show maximum_name_length
            ++ ", "
            ++ "\""
            ++ public_name
            ++ "\""
            ++ ", "
            ++ show extensions
            ++ ")"

instance SizeOf ECHConfigContents where
    sizeof ECHConfigContents{..} =
        sizeof key_config
            + 4
            + BS.length (C8.pack public_name)
            + sum (map sizeof extensions)

getECHConfigContents :: ReadBuffer -> IO ECHConfigContents
getECHConfigContents rbuf = do
    kcf <- getHpkeKeyConfig rbuf
    mnl <- read8 rbuf
    pn <- C8.unpack <$> getOpaque8 rbuf
    exts <- getList16 rbuf getECHConfigExtension
    return $ ECHConfigContents kcf mnl pn exts

putECHConfigContents :: WriteBuffer -> ECHConfigContents -> IO ()
putECHConfigContents wbuf ECHConfigContents{..} = do
    putHpkeKeyConfig wbuf key_config
    write8 wbuf maximum_name_length
    putOpaque8 wbuf $ C8.pack public_name
    putList16 wbuf putECHConfigExtension extensions

----------------------------------------------------------------

-- | Type for configuration of encrypted client hello.
newtype ECHConfig = ECHConfig
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

sizeOfECHConfig :: ECHConfig -> Int
sizeOfECHConfig = sizeof

-- | Encoder for 'ECHConfig'.
encodeECHConfig :: ECHConfig -> ByteString
encodeECHConfig cnf = unsafePerformIO $ withWriteBuffer siz $ \wbuf -> putECHConfig wbuf cnf
  where
    siz = sizeOfECHConfig cnf

-- | Decoder for 'ECHConfig'.
decodeECHConfig :: ByteString -> Maybe ECHConfig
decodeECHConfig bs =
    unsafePerformIO $
        E.handle handler $
            withReadBuffer bs $
                \rbuf -> Just <$> getECHConfig rbuf
  where
    handler (E.SomeException _) = return Nothing

----------------------------------------------------------------

-- | A list of 'ECHConfig'.
type ECHConfigList = [ECHConfig]

getECHConfigList :: ReadBuffer -> IO [ECHConfig]
getECHConfigList rbuf = getList16 rbuf getECHConfig

putECHConfigList :: WriteBuffer -> [ECHConfig] -> IO ()
putECHConfigList wbuf configs =
    putList16 wbuf putECHConfig configs

sizeOfECHConfigList :: [ECHConfig] -> Int
sizeOfECHConfigList configs = sum (map sizeOfECHConfig configs) + 2

-- | Encoder for 'ECHConfigList'.
encodeECHConfigList :: [ECHConfig] -> ByteString
encodeECHConfigList configs = unsafePerformIO $ withWriteBuffer siz $ \wbuf ->
    putECHConfigList wbuf configs
  where
    siz = sizeOfECHConfigList configs

-- | Decoder for 'ECHConfigList'.
decodeECHConfigList :: ByteString -> Maybe [ECHConfig]
decodeECHConfigList bs =
    unsafePerformIO $
        E.handle handler $
            withReadBuffer bs $
                \rbuf -> Just <$> getECHConfigList rbuf
  where
    handler (E.SomeException _) = return Nothing

-- | Loading the wire format of 'ECHConfigList' and
--   decode it into 'ECHConfigList'.
loadECHConfigList :: FilePath -> IO [ECHConfig]
loadECHConfigList file = do
    bs <- C8.readFile file
    withReadBuffer bs getECHConfigList

-- | Loading secret keys stored in files whose names
-- are "\<num\>.key".
--
-- > loadECHSecretKeys ["0.key", "1.key"]
loadECHSecretKeys :: [FilePath] -> IO [(ConfigId, ByteString)]
loadECHSecretKeys files = mapM loadECHSecretKey files
  where
    loadECHSecretKey file = do
        let numstr = takeWhile isDigit $ takeFileName file
            key = read numstr :: ConfigId
        val <- C8.readFile file
        return (key, val)

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
                loop lim (build . (x :))
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
