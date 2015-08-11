-- |
-- Module      : Network.TLS.Extra.Cipher
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
{-# LANGUAGE CPP #-}
{-# LANGUAGE PackageImports #-}
module Network.TLS.Extra.Cipher
    (
    -- * cipher suite
      ciphersuite_all
    , ciphersuite_medium
    , ciphersuite_strong
    , ciphersuite_unencrypted
    , ciphersuite_dhe_rsa
    , ciphersuite_dhe_dss
    -- * individual ciphers
    , cipher_null_SHA1
    , cipher_null_MD5
    , cipher_RC4_128_MD5
    , cipher_RC4_128_SHA1
    , cipher_AES128_SHA1
    , cipher_AES256_SHA1
    , cipher_AES128_SHA256
    , cipher_AES256_SHA256
    , cipher_RSA_3DES_EDE_CBC_SHA1
    , cipher_DHE_RSA_AES128_SHA1
    , cipher_DHE_RSA_AES256_SHA1
    , cipher_DHE_RSA_AES128_SHA256
    , cipher_DHE_RSA_AES256_SHA256
    , cipher_DHE_DSS_AES128_SHA1
    , cipher_DHE_DSS_AES256_SHA1
    , cipher_DHE_DSS_RC4_SHA1
    , cipher_DHE_RSA_AES128GCM_SHA256
    , cipher_ECDHE_RSA_AES128GCM_SHA256
    , cipher_ECDHE_RSA_AES128CBC_SHA256
    , cipher_ECDHE_RSA_AES128CBC_SHA
    ) where

import qualified Data.ByteString as B

import Network.TLS (Version(..))
import Network.TLS.Cipher
import Data.Tuple (swap)

import Crypto.Cipher.AES
import qualified Crypto.Cipher.RC4 as RC4
import Crypto.Cipher.TripleDES
import Crypto.Cipher.Types hiding (Cipher, cipherName)
import Crypto.Error

takelast :: Int -> B.ByteString -> B.ByteString
takelast i b = B.drop (B.length b - i) b

aes128cbc :: BulkDirection -> BulkKey -> BulkBlock
aes128cbc BulkEncrypt key =
    let ctx = noFail (cipherInit key) :: AES128
     in (\iv input -> let output = cbcEncrypt ctx (makeIV_ iv) input in (output, takelast 16 output))
aes128cbc BulkDecrypt key =
    let ctx = noFail (cipherInit key) :: AES128
     in (\iv input -> let output = cbcDecrypt ctx (makeIV_ iv) input in (output, takelast 16 input))

aes256cbc :: BulkDirection -> BulkKey -> BulkBlock
aes256cbc BulkEncrypt key =
    let ctx = noFail (cipherInit key) :: AES256
     in (\iv input -> let output = cbcEncrypt ctx (makeIV_ iv) input in (output, takelast 16 output))
aes256cbc BulkDecrypt key =
    let ctx = noFail (cipherInit key) :: AES256
     in (\iv input -> let output = cbcDecrypt ctx (makeIV_ iv) input in (output, takelast 16 input))

aes128gcm :: BulkDirection -> BulkKey -> BulkAEAD
aes128gcm BulkEncrypt key =
    let ctx = noFail (cipherInit key) :: AES128
     in (\nonce d ad ->
            let aeadIni = noFail (aeadInit AEAD_GCM ctx nonce)
             in swap $ aeadSimpleEncrypt aeadIni ad d 16)
aes128gcm BulkDecrypt key =
    let ctx = noFail (cipherInit key) :: AES128
     in (\nonce d ad ->
            let aeadIni = noFail (aeadInit AEAD_GCM ctx nonce)
             in simpleDecrypt aeadIni ad d)
  where
    simpleDecrypt aeadIni header input = (output, tag)
      where
            aead                = aeadAppendHeader aeadIni header
            (output, aeadFinal) = aeadDecrypt aead input
            tag                 = aeadFinalize aeadFinal 16

noFail :: CryptoFailable a -> a
noFail = throwCryptoError

makeIV_ :: BlockCipher a => B.ByteString -> IV a
makeIV_ = maybe (error "makeIV_") id . makeIV

tripledes_ede :: BulkDirection -> BulkKey -> BulkBlock
tripledes_ede BulkEncrypt key =
    let ctx = noFail $ cipherInit key
     in (\iv input -> let output = cbcEncrypt ctx (tripledes_iv iv) input in (output, takelast 16 output))
tripledes_ede BulkDecrypt key =
    let ctx = noFail $ cipherInit key
     in (\iv input -> let output = cbcDecrypt ctx (tripledes_iv iv) input in (output, takelast 16 input))

tripledes_iv :: BulkIV -> IV DES_EDE3
tripledes_iv iv = maybe (error "tripledes cipher iv internal error") id $ makeIV iv

rc4 :: BulkDirection -> BulkKey -> BulkStream
rc4 _ bulkKey = BulkStream (combineRC4 $ RC4.initialize bulkKey)
  where
    combineRC4 ctx input =
        let (ctx', output) = RC4.combine ctx input
         in (output, BulkStream (combineRC4 ctx'))


-- | all encrypted ciphers supported ordered from strong to weak.
-- this choice of ciphersuite should satisfy most normal need
ciphersuite_all :: [Cipher]
ciphersuite_all =
    [ cipher_DHE_RSA_AES256_SHA256, cipher_DHE_RSA_AES128_SHA256
    , cipher_DHE_RSA_AES256_SHA1, cipher_DHE_RSA_AES128_SHA1
    , cipher_DHE_DSS_AES256_SHA1, cipher_DHE_DSS_AES128_SHA1
    , cipher_AES128_SHA256, cipher_AES256_SHA256
    , cipher_AES128_SHA1,   cipher_AES256_SHA1
    , cipher_DHE_DSS_RC4_SHA1, cipher_RC4_128_SHA1,  cipher_RC4_128_MD5
    , cipher_RSA_3DES_EDE_CBC_SHA1
    , cipher_DHE_RSA_AES128GCM_SHA256
    ]

-- | list of medium ciphers.
ciphersuite_medium :: [Cipher]
ciphersuite_medium = [cipher_RC4_128_MD5, cipher_RC4_128_SHA1, cipher_AES128_SHA1, cipher_AES256_SHA1]

-- | the strongest ciphers supported.
ciphersuite_strong :: [Cipher]
ciphersuite_strong = [cipher_DHE_RSA_AES256_SHA256, cipher_AES256_SHA256, cipher_AES256_SHA1]

-- | DHE-RSA cipher suite
ciphersuite_dhe_rsa :: [Cipher]
ciphersuite_dhe_rsa = [cipher_DHE_RSA_AES256_SHA256, cipher_DHE_RSA_AES128_SHA256
                      , cipher_DHE_RSA_AES256_SHA1, cipher_DHE_RSA_AES128_SHA1
                      , cipher_DHE_RSA_AES128GCM_SHA256]

ciphersuite_dhe_dss :: [Cipher]
ciphersuite_dhe_dss = [cipher_DHE_DSS_AES256_SHA1, cipher_DHE_DSS_AES128_SHA1, cipher_DHE_DSS_RC4_SHA1]

-- | all unencrypted ciphers, do not use on insecure network.
ciphersuite_unencrypted :: [Cipher]
ciphersuite_unencrypted = [cipher_null_MD5, cipher_null_SHA1]

bulk_null, bulk_rc4, bulk_aes128, bulk_aes256, bulk_tripledes_ede, bulk_aes128gcm :: Bulk
bulk_null = Bulk
    { bulkName         = "null"
    , bulkKeySize      = 0
    , bulkIVSize       = 0
    , bulkExplicitIV   = 0
    , bulkAuthTagLen   = 0
    , bulkBlockSize    = 0
    , bulkF            = BulkStreamF passThrough
    }
  where
    passThrough _ _ = BulkStream go where go inp = (inp, BulkStream go)

bulk_rc4 = Bulk
    { bulkName         = "RC4-128"
    , bulkKeySize      = 16
    , bulkIVSize       = 0
    , bulkExplicitIV   = 0
    , bulkAuthTagLen   = 0
    , bulkBlockSize    = 0
    , bulkF            = BulkStreamF rc4
    }

bulk_aes128 = Bulk
    { bulkName         = "AES128"
    , bulkKeySize      = 16
    , bulkIVSize       = 16
    , bulkExplicitIV   = 0
    , bulkAuthTagLen   = 0
    , bulkBlockSize    = 16
    , bulkF            = BulkBlockF aes128cbc
    }

bulk_aes128gcm = Bulk
    { bulkName         = "AES128GCM"
    , bulkKeySize      = 16 -- RFC 5116 Sec 5.1: K_LEN
    , bulkIVSize       = 4  -- RFC 5288 GCMNonce.salt, fixed_iv_length
    , bulkExplicitIV   = 8
    , bulkAuthTagLen   = 16
    , bulkBlockSize    = 0  -- dummy, not used
    , bulkF            = BulkAeadF aes128gcm
    }

bulk_aes256 = Bulk
    { bulkName         = "AES256"
    , bulkKeySize      = 32
    , bulkIVSize       = 16
    , bulkExplicitIV   = 0
    , bulkAuthTagLen   = 0
    , bulkBlockSize    = 16
    , bulkF            = BulkBlockF aes256cbc
    }

bulk_tripledes_ede = Bulk
    { bulkName      = "3DES-EDE-CBC"
    , bulkKeySize   = 24
    , bulkIVSize    = 8
    , bulkExplicitIV = 0
    , bulkAuthTagLen = 0
    , bulkBlockSize = 8
    , bulkF         = BulkBlockF tripledes_ede
    }

-- | unencrypted cipher using RSA for key exchange and MD5 for digest
cipher_null_MD5 :: Cipher
cipher_null_MD5 = Cipher
    { cipherID           = 0x1
    , cipherName         = "RSA-null-MD5"
    , cipherBulk         = bulk_null
    , cipherHash         = MD5
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Nothing
    }

-- | unencrypted cipher using RSA for key exchange and SHA1 for digest
cipher_null_SHA1 :: Cipher
cipher_null_SHA1 = Cipher
    { cipherID           = 0x2
    , cipherName         = "RSA-null-SHA1"
    , cipherBulk         = bulk_null
    , cipherHash         = SHA1
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Nothing
    }

-- | RC4 cipher, RSA key exchange and MD5 for digest
cipher_RC4_128_MD5 :: Cipher
cipher_RC4_128_MD5 = Cipher
    { cipherID           = 0x04
    , cipherName         = "RSA-rc4-128-md5"
    , cipherBulk         = bulk_rc4
    , cipherHash         = MD5
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Nothing
    }

-- | RC4 cipher, RSA key exchange and SHA1 for digest
cipher_RC4_128_SHA1 :: Cipher
cipher_RC4_128_SHA1 = Cipher
    { cipherID           = 0x05
    , cipherName         = "RSA-rc4-128-sha1"
    , cipherBulk         = bulk_rc4
    , cipherHash         = SHA1
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Nothing
    }

-- | AES cipher (128 bit key), RSA key exchange and SHA1 for digest
cipher_AES128_SHA1 :: Cipher
cipher_AES128_SHA1 = Cipher
    { cipherID           = 0x2f
    , cipherName         = "RSA-aes128-sha1"
    , cipherBulk         = bulk_aes128
    , cipherHash         = SHA1
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Just SSL3
    }

-- | AES cipher (256 bit key), RSA key exchange and SHA1 for digest
cipher_AES256_SHA1 :: Cipher
cipher_AES256_SHA1 = Cipher
    { cipherID           = 0x35
    , cipherName         = "RSA-aes256-sha1"
    , cipherBulk         = bulk_aes256
    , cipherHash         = SHA1
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Just SSL3
    }

-- | AES cipher (128 bit key), RSA key exchange and SHA256 for digest
cipher_AES128_SHA256 :: Cipher
cipher_AES128_SHA256 = Cipher
    { cipherID           = 0x3c
    , cipherName         = "RSA-aes128-sha256"
    , cipherBulk         = bulk_aes128
    , cipherHash         = SHA256
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Just TLS12
    }

-- | AES cipher (256 bit key), RSA key exchange and SHA256 for digest
cipher_AES256_SHA256 :: Cipher
cipher_AES256_SHA256 = Cipher
    { cipherID           = 0x3d
    , cipherName         = "RSA-aes256-sha256"
    , cipherBulk         = bulk_aes256
    , cipherHash         = SHA256
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Just TLS12
    }

-- | AES cipher (128 bit key), DHE key exchanged signed by RSA and SHA1 for digest
cipher_DHE_RSA_AES128_SHA1 :: Cipher
cipher_DHE_RSA_AES128_SHA1 = Cipher
    { cipherID           = 0x33
    , cipherName         = "DHE-RSA-AES128-SHA1"
    , cipherBulk         = bulk_aes128
    , cipherHash         = SHA1
    , cipherKeyExchange  = CipherKeyExchange_DHE_RSA
    , cipherMinVer       = Nothing
    }

-- | AES cipher (256 bit key), DHE key exchanged signed by RSA and SHA1 for digest
cipher_DHE_RSA_AES256_SHA1 :: Cipher
cipher_DHE_RSA_AES256_SHA1 = cipher_DHE_RSA_AES128_SHA1
    { cipherID           = 0x39
    , cipherName         = "DHE-RSA-AES256-SHA1"
    , cipherBulk         = bulk_aes256
    }

-- | AES cipher (128 bit key), DHE key exchanged signed by DSA and SHA1 for digest
cipher_DHE_DSS_AES128_SHA1 :: Cipher
cipher_DHE_DSS_AES128_SHA1 = Cipher
    { cipherID           = 0x32
    , cipherName         = "DHE-DSA-AES128-SHA1"
    , cipherBulk         = bulk_aes128
    , cipherHash         = SHA1
    , cipherKeyExchange  = CipherKeyExchange_DHE_DSS
    , cipherMinVer       = Nothing
    }

-- | AES cipher (256 bit key), DHE key exchanged signed by DSA and SHA1 for digest
cipher_DHE_DSS_AES256_SHA1 :: Cipher
cipher_DHE_DSS_AES256_SHA1 = cipher_DHE_DSS_AES128_SHA1
    { cipherID           = 0x38
    , cipherName         = "DHE-DSA-AES256-SHA1"
    , cipherBulk         = bulk_aes256
    }

cipher_DHE_DSS_RC4_SHA1 :: Cipher
cipher_DHE_DSS_RC4_SHA1 = cipher_DHE_DSS_AES128_SHA1
    { cipherID           = 0x66
    , cipherName         = "DHE-DSA-RC4-SHA1"
    , cipherBulk         = bulk_rc4
    }

cipher_DHE_RSA_AES128_SHA256 :: Cipher
cipher_DHE_RSA_AES128_SHA256 = cipher_DHE_RSA_AES128_SHA1
    { cipherID           = 0x67
    , cipherName         = "DHE-RSA-AES128-SHA256"
    , cipherHash         = SHA256
    , cipherMinVer       = Just TLS12
    }

cipher_DHE_RSA_AES256_SHA256 :: Cipher
cipher_DHE_RSA_AES256_SHA256 = cipher_DHE_RSA_AES128_SHA256
    { cipherID           = 0x6b
    , cipherName         = "DHE-RSA-AES256-SHA256"
    , cipherBulk         = bulk_aes256
    }

-- | 3DES cipher (168 bit key), RSA key exchange and SHA1 for digest
cipher_RSA_3DES_EDE_CBC_SHA1 :: Cipher
cipher_RSA_3DES_EDE_CBC_SHA1 = Cipher
    { cipherID           = 0x0a
    , cipherName         = "RSA-3DES-EDE-CBC-SHA1"
    , cipherBulk         = bulk_tripledes_ede
    , cipherHash         = SHA1
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Nothing
    }

cipher_DHE_RSA_AES128GCM_SHA256 :: Cipher
cipher_DHE_RSA_AES128GCM_SHA256 = Cipher
    { cipherID           = 0x9e
    , cipherName         = "DHE-RSA-AES128GCM-SHA256"
    , cipherBulk         = bulk_aes128gcm
    , cipherHash         = SHA256
    , cipherKeyExchange  = CipherKeyExchange_DHE_RSA
    , cipherMinVer       = Just TLS12 -- RFC 5288 Sec 4
    }

cipher_ECDHE_RSA_AES128GCM_SHA256 :: Cipher
cipher_ECDHE_RSA_AES128GCM_SHA256 = Cipher
    { cipherID           = 0xc02f
    , cipherName         = "ECDHE-RSA-AES128GCM-SHA256"
    , cipherBulk         = bulk_aes128gcm
    , cipherHash         = SHA256
    , cipherKeyExchange  = CipherKeyExchange_ECDHE_RSA
    , cipherMinVer       = Just TLS12 -- RFC 5288 Sec 4
    }

cipher_ECDHE_RSA_AES128CBC_SHA :: Cipher
cipher_ECDHE_RSA_AES128CBC_SHA = Cipher
    { cipherID           = 0xc013
    , cipherName         = "ECDHE-RSA-AES128CBC-SHA"
    , cipherBulk         = bulk_aes128
    , cipherHash         = SHA1
    , cipherKeyExchange  = CipherKeyExchange_ECDHE_RSA
    , cipherMinVer       = Just TLS10
    }

--TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 
cipher_ECDHE_RSA_AES128CBC_SHA256 :: Cipher
cipher_ECDHE_RSA_AES128CBC_SHA256 = Cipher
    { cipherID           = 0xc027
    , cipherName         = "ECDHE-RSA-AES128CBC-SHA"
    , cipherBulk         = bulk_aes128
    , cipherHash         = SHA256
    , cipherKeyExchange  = CipherKeyExchange_ECDHE_RSA
    , cipherMinVer       = Just TLS12 -- RFC 5288 Sec 4
    }

{-
TLS 1.0 ciphers definition

CipherSuite TLS_NULL_WITH_NULL_NULL               = { 0x00,0x00 };
CipherSuite TLS_RSA_WITH_NULL_MD5                 = { 0x00,0x01 };
CipherSuite TLS_RSA_WITH_NULL_SHA                 = { 0x00,0x02 };
CipherSuite TLS_RSA_EXPORT_WITH_RC4_40_MD5        = { 0x00,0x03 };
CipherSuite TLS_RSA_WITH_RC4_128_MD5              = { 0x00,0x04 };
CipherSuite TLS_RSA_WITH_RC4_128_SHA              = { 0x00,0x05 };
CipherSuite TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5    = { 0x00,0x06 };
CipherSuite TLS_RSA_WITH_IDEA_CBC_SHA             = { 0x00,0x07 };
CipherSuite TLS_RSA_EXPORT_WITH_DES40_CBC_SHA     = { 0x00,0x08 };
CipherSuite TLS_RSA_WITH_DES_CBC_SHA              = { 0x00,0x09 };
CipherSuite TLS_RSA_WITH_3DES_EDE_CBC_SHA         = { 0x00,0x0A };
CipherSuite TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA  = { 0x00,0x0B };
CipherSuite TLS_DH_DSS_WITH_DES_CBC_SHA           = { 0x00,0x0C };
CipherSuite TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA      = { 0x00,0x0D };
CipherSuite TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA  = { 0x00,0x0E };
CipherSuite TLS_DH_RSA_WITH_DES_CBC_SHA           = { 0x00,0x0F };
CipherSuite TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA      = { 0x00,0x10 };
CipherSuite TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = { 0x00,0x11 };
CipherSuite TLS_DHE_DSS_WITH_DES_CBC_SHA          = { 0x00,0x12 };
CipherSuite TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA     = { 0x00,0x13 };
CipherSuite TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = { 0x00,0x14 };
CipherSuite TLS_DHE_RSA_WITH_DES_CBC_SHA          = { 0x00,0x15 };
CipherSuite TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA     = { 0x00,0x16 };
CipherSuite TLS_DH_anon_EXPORT_WITH_RC4_40_MD5    = { 0x00,0x17 };
CipherSuite TLS_DH_anon_WITH_RC4_128_MD5          = { 0x00,0x18 };
CipherSuite TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = { 0x00,0x19 };
CipherSuite TLS_DH_anon_WITH_DES_CBC_SHA          = { 0x00,0x1A };
CipherSuite TLS_DH_anon_WITH_3DES_EDE_CBC_SHA     = { 0x00,0x1B };

TLS-DHE-RSA-WITH-AES-128-CBC-SHA     {0x00,0x33}
TLS-DHE-RSA-WITH-AES-256-CBC-SHA     {0x00,0x39}
TLS-DHE-RSA-WITH-AES-128-CBC-SHA256   {0x00,0x67}
TLS-DHE-RSA-WITH-AES-256-CBC-SHA256   {0x00,0x6B}
TLS-DHE-RSA-WITH-AES-128-GCM-SHA256   {0x00,0x9E}
TLS-DHE-RSA-WITH-AES-256-GCM-SHA384   {0x00,0x9F}
TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA   {0x00,0x45}
TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA   {0x00,0x88}
TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256      {0x00,0xBE}
TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256      {0x00,0xC4}
TLS-DHE-RSA-WITH-CAMELLIA-128-GCM-SHA256      {0x00,0x7C}
TLS-DHE-RSA-WITH-CAMELLIA-256-GCM-SHA256      {0x00,0x7D}
TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA      {0x00,0x16}
TLS-DHE-RSA-WITH-DES-CBC-SHA    {0x00,0x15}

TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA     {0xC0,0x13}
TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA     {0xC0,0x14}
TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256   {0xC0,0x27}
TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384   {0xC0,0x28}
TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256   {0xC0,0x2F}
TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384   {0xC0,0x30}
TLS-ECDHE-RSA-WITH-CAMELLIA-128-CBC-SHA256    {0xC0,0x76}
TLS-ECDHE-RSA-WITH-CAMELLIA-256-CBC-SHA384    {0xC0,0x77}
TLS-ECDHE-RSA-WITH-CAMELLIA-128-GCM-SHA256    {0xC0,0x8A}
TLS-ECDHE-RSA-WITH-CAMELLIA-256-GCM-SHA384    {0xC0,0x8B}
TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA  {0xC0,0x12}
TLS-ECDHE-RSA-WITH-RC4-128-SHA    {0xC0,0x11}
TLS-ECDHE-RSA-WITH-NULL-SHA  {0xC0,0x10}

TLS-PSK-WITH-RC4-128-SHA    {0x00,0x8A}
TLS-PSK-WITH-3DES-EDE-CBC-SHA      {0x00,0x8B}
TLS-PSK-WITH-AES-128-CBC-SHA     {0x00,0x8C}
TLS-PSK-WITH-AES-256-CBC-SHA     {0x00,0x8D}
TLS-PSK-WITH-AES-128-CBC-SHA256   {0x00,0xAE}
TLS-PSK-WITH-AES-256-CBC-SHA384   {0x00,0xAF}
TLS-PSK-WITH-AES-128-GCM-SHA256   {0x00,0xA8}
TLS-PSK-WITH-AES-256-GCM-SHA384   {0x00,0xA9}
TLS-PSK-WITH-CAMELLIA-128-CBC-SHA256      {0xC0,0x94}
TLS-PSK-WITH-CAMELLIA-256-CBC-SHA384      {0xC0,0x95}
TLS-PSK-WITH-CAMELLIA-128-GCM-SHA256      {0xC0,0x8D}
TLS-PSK-WITH-CAMELLIA-256-GCM-SHA384      {0xC0,0x8F}
TLS-PSK-WITH-NULL-SHA     {0x00,0x2C}
TLS-PSK-WITH-NULL-SHA256      {0x00,0xB4}
TLS-PSK-WITH-NULL-SHA384      {0x00,0xB5}

best ciphers suite description:
    <http://www.thesprawl.org/research/tls-and-ssl-cipher-suites/>

-}
