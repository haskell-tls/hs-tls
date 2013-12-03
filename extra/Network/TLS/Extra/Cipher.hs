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
    -- * individual ciphers
    , cipher_null_SHA1
    , cipher_null_MD5
    , cipher_RC4_128_MD5
    , cipher_RC4_128_SHA1
    , cipher_AES128_SHA1
    , cipher_AES256_SHA1
    , cipher_AES128_SHA256
    , cipher_AES256_SHA256
    ) where

import qualified Data.ByteString as B

import Network.TLS (Version(..))
import Network.TLS.Cipher
import qualified "cipher-rc4" Crypto.Cipher.RC4 as RC4

import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.MD5 as MD5

import qualified "cipher-aes" Crypto.Cipher.AES as AES

aes_cbc_encrypt :: Key -> IV -> B.ByteString -> B.ByteString
aes_cbc_encrypt key iv d = AES.encryptCBC (AES.initAES key) iv d

aes_cbc_decrypt :: Key -> IV -> B.ByteString -> B.ByteString
aes_cbc_decrypt key iv d = AES.decryptCBC (AES.initAES key) iv d

aes128_cbc_encrypt = aes_cbc_encrypt
aes128_cbc_decrypt = aes_cbc_decrypt
aes256_cbc_encrypt = aes_cbc_encrypt
aes256_cbc_decrypt = aes_cbc_decrypt

toIV :: RC4.Ctx -> IV
toIV (RC4.Ctx ctx) = ctx

toCtx :: IV -> RC4.Ctx
toCtx iv = RC4.Ctx iv

initF_rc4 :: Key -> IV
initF_rc4 key     = toIV $ RC4.initCtx key

encryptF_rc4 :: IV -> B.ByteString -> (B.ByteString, IV)
encryptF_rc4 iv d = (\(ctx, e) -> (e, toIV ctx)) $ RC4.combine (toCtx iv) d

decryptF_rc4 :: IV -> B.ByteString -> (B.ByteString, IV)
decryptF_rc4 iv e = (\(ctx, d) -> (d, toIV ctx)) $ RC4.combine (toCtx iv) e


-- | all encrypted ciphers supported ordered from strong to weak.
-- this choice of ciphersuite should satisfy most normal need
ciphersuite_all :: [Cipher]
ciphersuite_all =
    [ cipher_AES128_SHA256, cipher_AES256_SHA256
    , cipher_AES128_SHA1,   cipher_AES256_SHA1
    , cipher_RC4_128_SHA1,  cipher_RC4_128_MD5
    ]

-- | list of medium ciphers.
ciphersuite_medium :: [Cipher]
ciphersuite_medium = [cipher_RC4_128_MD5, cipher_RC4_128_SHA1, cipher_AES128_SHA1, cipher_AES256_SHA1]

-- | the strongest ciphers supported.
ciphersuite_strong :: [Cipher]
ciphersuite_strong = [cipher_AES256_SHA256, cipher_AES256_SHA1]

-- | all unencrypted ciphers, do not use on insecure network.
ciphersuite_unencrypted :: [Cipher]
ciphersuite_unencrypted = [cipher_null_MD5, cipher_null_SHA1]

bulk_null = Bulk
    { bulkName         = "null"
    , bulkKeySize      = 0
    , bulkIVSize       = 0
    , bulkBlockSize    = 0
    , bulkF            = BulkStreamF (const B.empty) streamId streamId
    }
    where streamId = \iv b -> (b,iv)

bulk_rc4 = Bulk
    { bulkName         = "RC4-128"
    , bulkKeySize      = 16
    , bulkIVSize       = 0
    , bulkBlockSize    = 0
    , bulkF            = BulkStreamF initF_rc4 encryptF_rc4 decryptF_rc4
    }

bulk_aes128 = Bulk
    { bulkName         = "AES128"
    , bulkKeySize      = 16
    , bulkIVSize       = 16
    , bulkBlockSize    = 16
    , bulkF            = BulkBlockF aes128_cbc_encrypt aes128_cbc_decrypt
    }

bulk_aes256 = Bulk
    { bulkName         = "AES256"
    , bulkKeySize      = 32
    , bulkIVSize       = 16
    , bulkBlockSize    = 16
    , bulkF            = BulkBlockF aes256_cbc_encrypt aes256_cbc_decrypt
    }

hash_md5 = Hash
    { hashName = "MD5"
    , hashSize = 16
    , hashF    = MD5.hash
    }

hash_sha1 = Hash
    { hashName = "SHA1"
    , hashSize = 20
    , hashF    = SHA1.hash
    }

hash_sha256 = Hash
    { hashName = "SHA256"
    , hashSize = 32
    , hashF    = SHA256.hash
    }

-- | unencrypted cipher using RSA for key exchange and MD5 for digest
cipher_null_MD5 :: Cipher
cipher_null_MD5 = Cipher
    { cipherID           = 0x1
    , cipherName         = "RSA-null-MD5"
    , cipherBulk         = bulk_null
    , cipherHash         = hash_md5
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Nothing
    }

-- | unencrypted cipher using RSA for key exchange and SHA1 for digest
cipher_null_SHA1 :: Cipher
cipher_null_SHA1 = Cipher
    { cipherID           = 0x2
    , cipherName         = "RSA-null-SHA1"
    , cipherBulk         = bulk_null
    , cipherHash         = hash_sha1
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Nothing
    }

-- | RC4 cipher, RSA key exchange and MD5 for digest
cipher_RC4_128_MD5 :: Cipher
cipher_RC4_128_MD5 = Cipher
    { cipherID           = 0x04
    , cipherName         = "RSA-rc4-128-md5"
    , cipherBulk         = bulk_rc4
    , cipherHash         = hash_md5
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Nothing
    }

-- | RC4 cipher, RSA key exchange and SHA1 for digest
cipher_RC4_128_SHA1 :: Cipher
cipher_RC4_128_SHA1 = Cipher
    { cipherID           = 0x05
    , cipherName         = "RSA-rc4-128-sha1"
    , cipherBulk         = bulk_rc4
    , cipherHash         = hash_sha1
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Nothing
    }

-- | AES cipher (128 bit key), RSA key exchange and SHA1 for digest
cipher_AES128_SHA1 :: Cipher
cipher_AES128_SHA1 = Cipher
    { cipherID           = 0x2f
    , cipherName         = "RSA-aes128-sha1"
    , cipherBulk         = bulk_aes128
    , cipherHash         = hash_sha1
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Just SSL3
    }

-- | AES cipher (256 bit key), RSA key exchange and SHA1 for digest
cipher_AES256_SHA1 :: Cipher
cipher_AES256_SHA1 = Cipher
    { cipherID           = 0x35
    , cipherName         = "RSA-aes256-sha1"
    , cipherBulk         = bulk_aes256
    , cipherHash         = hash_sha1
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Just SSL3
    }

-- | AES cipher (128 bit key), RSA key exchange and SHA256 for digest
cipher_AES128_SHA256 :: Cipher
cipher_AES128_SHA256 = Cipher
    { cipherID           = 0x3c
    , cipherName         = "RSA-aes128-sha256"
    , cipherBulk         = bulk_aes128
    , cipherHash         = hash_sha256
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Just TLS12
    }

-- | AES cipher (256 bit key), RSA key exchange and SHA256 for digest
cipher_AES256_SHA256 :: Cipher
cipher_AES256_SHA256 = Cipher
    { cipherID           = 0x3d
    , cipherName         = "RSA-aes256-sha256"
    , cipherBulk         = bulk_aes256
    , cipherHash         = hash_sha256
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Just TLS12
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

-}
