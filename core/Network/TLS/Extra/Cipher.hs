-- |
-- Module      : Network.TLS.Extra.Cipher
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
{-# LANGUAGE CPP #-}
module Network.TLS.Extra.Cipher
    (
    -- * cipher suite
      ciphersuite_default
    , ciphersuite_all
    , ciphersuite_medium
    , ciphersuite_strong
    , ciphersuite_unencrypted
    , ciphersuite_dhe_rsa
    , ciphersuite_dhe_dss
    -- * individual ciphers
    , cipher_null_SHA1
    , cipher_AES128_SHA1
    , cipher_AES256_SHA1
    , cipher_AES128_SHA256
    , cipher_AES256_SHA256
    , cipher_AES128GCM_SHA256
    , cipher_AES256GCM_SHA384
    , cipher_DHE_RSA_AES128_SHA1
    , cipher_DHE_RSA_AES256_SHA1
    , cipher_DHE_RSA_AES128_SHA256
    , cipher_DHE_RSA_AES256_SHA256
    , cipher_DHE_DSS_AES128_SHA1
    , cipher_DHE_DSS_AES256_SHA1
    , cipher_DHE_RSA_AES128GCM_SHA256
    , cipher_DHE_RSA_AES256GCM_SHA384
    , cipher_ECDHE_RSA_AES128GCM_SHA256
    , cipher_ECDHE_RSA_AES256GCM_SHA384
    , cipher_ECDHE_RSA_AES128CBC_SHA256
    , cipher_ECDHE_RSA_AES128CBC_SHA
    , cipher_ECDHE_RSA_AES256CBC_SHA
    , cipher_ECDHE_RSA_AES256CBC_SHA384
    , cipher_ECDHE_ECDSA_AES128CBC_SHA
    , cipher_ECDHE_ECDSA_AES256CBC_SHA
    , cipher_ECDHE_ECDSA_AES128CBC_SHA256
    , cipher_ECDHE_ECDSA_AES256CBC_SHA384
    , cipher_ECDHE_ECDSA_AES128GCM_SHA256
    , cipher_ECDHE_ECDSA_AES256GCM_SHA384
    -- * obsolete and non-standard ciphers
    , cipher_RSA_3DES_EDE_CBC_SHA1
    , cipher_RC4_128_MD5
    , cipher_RC4_128_SHA1
    , cipher_null_MD5
    , cipher_DHE_DSS_RC4_SHA1
    ) where

import qualified Data.ByteString as B

import Network.TLS.Types (Version(..))
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

aes256gcm :: BulkDirection -> BulkKey -> BulkAEAD
aes256gcm BulkEncrypt key =
    let ctx = noFail (cipherInit key) :: AES256
     in (\nonce d ad ->
            let aeadIni = noFail (aeadInit AEAD_GCM ctx nonce)
             in swap $ aeadSimpleEncrypt aeadIni ad d 16)
aes256gcm BulkDecrypt key =
    let ctx = noFail (cipherInit key) :: AES256
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
     in (\iv input -> let output = cbcEncrypt ctx (tripledes_iv iv) input in (output, takelast 8 output))
tripledes_ede BulkDecrypt key =
    let ctx = noFail $ cipherInit key
     in (\iv input -> let output = cbcDecrypt ctx (tripledes_iv iv) input in (output, takelast 8 input))

tripledes_iv :: BulkIV -> IV DES_EDE3
tripledes_iv iv = maybe (error "tripledes cipher iv internal error") id $ makeIV iv

rc4 :: BulkDirection -> BulkKey -> BulkStream
rc4 _ bulkKey = BulkStream (combineRC4 $ RC4.initialize bulkKey)
  where
    combineRC4 ctx input =
        let (ctx', output) = RC4.combine ctx input
         in (output, BulkStream (combineRC4 ctx'))

-- | All AES ciphers supported ordered from strong to weak.  This choice
-- of ciphersuites should satisfy most normal needs.  For otherwise strong
-- ciphers we make little distinction between AES128 and AES256, and list
-- each but the weakest of the AES128 ciphers ahead of the corresponding AES256
-- ciphers.
ciphersuite_default :: [Cipher]
ciphersuite_default =
    [        -- First the PFS + GCM + SHA2 ciphers
      cipher_ECDHE_ECDSA_AES128GCM_SHA256, cipher_ECDHE_ECDSA_AES256GCM_SHA384
    , cipher_ECDHE_RSA_AES128GCM_SHA256, cipher_ECDHE_RSA_AES256GCM_SHA384
    , cipher_DHE_RSA_AES128GCM_SHA256, cipher_DHE_RSA_AES256GCM_SHA384
             -- Next the PFS + CBC + SHA2 ciphers
    , cipher_ECDHE_ECDSA_AES128CBC_SHA256, cipher_ECDHE_ECDSA_AES256CBC_SHA384
    , cipher_ECDHE_RSA_AES128CBC_SHA256, cipher_ECDHE_RSA_AES256CBC_SHA384
    , cipher_DHE_RSA_AES128_SHA256, cipher_DHE_RSA_AES256_SHA256
             -- Next the PFS + CBC + SHA1 ciphers
    , cipher_ECDHE_ECDSA_AES128CBC_SHA, cipher_ECDHE_ECDSA_AES256CBC_SHA
    , cipher_ECDHE_RSA_AES128CBC_SHA, cipher_ECDHE_RSA_AES256CBC_SHA
    , cipher_DHE_RSA_AES128_SHA1, cipher_DHE_RSA_AES256_SHA1
             -- Next the non-PFS + GCM + SHA2 ciphers
    , cipher_AES128GCM_SHA256, cipher_AES256GCM_SHA384
             -- Next the non-PFS + CBC + SHA2 ciphers
    , cipher_AES256_SHA256, cipher_AES128_SHA256
             -- Next the non-PFS + CBC + SHA1 ciphers
    , cipher_AES256_SHA1, cipher_AES128_SHA1
             -- Nobody uses or should use DSS, RC4,  3DES or MD5
    -- , cipher_DHE_DSS_AES256_SHA1, cipher_DHE_DSS_AES128_SHA1
    -- , cipher_DHE_DSS_RC4_SHA1, cipher_RC4_128_SHA1, cipher_RC4_128_MD5
    -- , cipher_RSA_3DES_EDE_CBC_SHA1
    ]

-- | The default ciphersuites + some not recommended last resort ciphers.
ciphersuite_all :: [Cipher]
ciphersuite_all = ciphersuite_default ++
    [ cipher_DHE_DSS_AES256_SHA1, cipher_DHE_DSS_AES128_SHA1
    , cipher_RSA_3DES_EDE_CBC_SHA1
    , cipher_RC4_128_SHA1
    ]

-- | list of medium ciphers.
ciphersuite_medium :: [Cipher]
ciphersuite_medium = [ cipher_RC4_128_SHA1
                     , cipher_AES128_SHA1
                     ]

-- | The strongest ciphers supported.  For ciphers with PFS, AEAD and SHA2, we
-- list each AES128 variant right after the corresponding AES256 variant.  For
-- weaker constructs, we use just the AES256 form.
ciphersuite_strong :: [Cipher]
ciphersuite_strong =
    [        -- If we have PFS + AEAD + SHA2, then allow AES128, else just 256
      cipher_ECDHE_ECDSA_AES256GCM_SHA384, cipher_ECDHE_ECDSA_AES128GCM_SHA256
    , cipher_ECDHE_RSA_AES256GCM_SHA384, cipher_ECDHE_RSA_AES128GCM_SHA256
    , cipher_DHE_RSA_AES256GCM_SHA384, cipher_DHE_RSA_AES128GCM_SHA256
             -- No AEAD
    , cipher_ECDHE_ECDSA_AES256CBC_SHA384
    , cipher_ECDHE_RSA_AES256CBC_SHA384
    , cipher_DHE_RSA_AES256_SHA256
             -- No SHA2
    , cipher_ECDHE_ECDSA_AES256CBC_SHA
    , cipher_ECDHE_RSA_AES256CBC_SHA
    , cipher_DHE_RSA_AES256_SHA1
             -- No PFS
    , cipher_AES256GCM_SHA384
             -- Neither PFS nor AEAD, just SHA2
    , cipher_AES256_SHA256
             -- Last resort no PFS, AEAD or SHA2
    , cipher_AES256_SHA1
    ]

-- | DHE-RSA cipher suite
ciphersuite_dhe_rsa :: [Cipher]
ciphersuite_dhe_rsa = [ cipher_DHE_RSA_AES256GCM_SHA384, cipher_DHE_RSA_AES128GCM_SHA256
                      , cipher_DHE_RSA_AES256_SHA256, cipher_DHE_RSA_AES128_SHA256
                      , cipher_DHE_RSA_AES256_SHA1, cipher_DHE_RSA_AES128_SHA1
                      ]

ciphersuite_dhe_dss :: [Cipher]
ciphersuite_dhe_dss = [cipher_DHE_DSS_AES256_SHA1, cipher_DHE_DSS_AES128_SHA1, cipher_DHE_DSS_RC4_SHA1]

-- | all unencrypted ciphers, do not use on insecure network.
ciphersuite_unencrypted :: [Cipher]
ciphersuite_unencrypted = [cipher_null_MD5, cipher_null_SHA1]

bulk_null, bulk_rc4, bulk_aes128, bulk_aes256, bulk_tripledes_ede, bulk_aes128gcm, bulk_aes256gcm :: Bulk
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

bulk_aes256gcm = Bulk
    { bulkName         = "AES256GCM"
    , bulkKeySize      = 32 -- RFC 5116 Sec 5.1: K_LEN
    , bulkIVSize       = 4  -- RFC 5288 GCMNonce.salt, fixed_iv_length
    , bulkExplicitIV   = 8
    , bulkAuthTagLen   = 16
    , bulkBlockSize    = 0  -- dummy, not used
    , bulkF            = BulkAeadF aes256gcm
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
    { cipherID           = 0x0001
    , cipherName         = "RSA-null-MD5"
    , cipherBulk         = bulk_null
    , cipherHash         = MD5
    , cipherPRFHash      = Nothing
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Nothing
    }

-- | unencrypted cipher using RSA for key exchange and SHA1 for digest
cipher_null_SHA1 :: Cipher
cipher_null_SHA1 = Cipher
    { cipherID           = 0x0002
    , cipherName         = "RSA-null-SHA1"
    , cipherBulk         = bulk_null
    , cipherHash         = SHA1
    , cipherPRFHash      = Nothing
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Nothing
    }

-- | RC4 cipher, RSA key exchange and MD5 for digest
cipher_RC4_128_MD5 :: Cipher
cipher_RC4_128_MD5 = Cipher
    { cipherID           = 0x0004
    , cipherName         = "RSA-rc4-128-md5"
    , cipherBulk         = bulk_rc4
    , cipherHash         = MD5
    , cipherPRFHash      = Nothing
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Nothing
    }

-- | RC4 cipher, RSA key exchange and SHA1 for digest
cipher_RC4_128_SHA1 :: Cipher
cipher_RC4_128_SHA1 = Cipher
    { cipherID           = 0x0005
    , cipherName         = "RSA-rc4-128-sha1"
    , cipherBulk         = bulk_rc4
    , cipherHash         = SHA1
    , cipherPRFHash      = Nothing
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Nothing
    }

-- | AES cipher (128 bit key), RSA key exchange and SHA1 for digest
cipher_AES128_SHA1 :: Cipher
cipher_AES128_SHA1 = Cipher
    { cipherID           = 0x002F
    , cipherName         = "RSA-AES128-SHA1"
    , cipherBulk         = bulk_aes128
    , cipherHash         = SHA1
    , cipherPRFHash      = Nothing
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Just SSL3
    }

-- | AES cipher (128 bit key), DHE key exchanged signed by DSA and SHA1 for digest
cipher_DHE_DSS_AES128_SHA1 :: Cipher
cipher_DHE_DSS_AES128_SHA1 = Cipher
    { cipherID           = 0x0032
    , cipherName         = "DHE-DSA-AES128-SHA1"
    , cipherBulk         = bulk_aes128
    , cipherHash         = SHA1
    , cipherPRFHash      = Nothing
    , cipherKeyExchange  = CipherKeyExchange_DHE_DSS
    , cipherMinVer       = Nothing
    }

-- | AES cipher (128 bit key), DHE key exchanged signed by RSA and SHA1 for digest
cipher_DHE_RSA_AES128_SHA1 :: Cipher
cipher_DHE_RSA_AES128_SHA1 = Cipher
    { cipherID           = 0x0033
    , cipherName         = "DHE-RSA-AES128-SHA1"
    , cipherBulk         = bulk_aes128
    , cipherHash         = SHA1
    , cipherPRFHash      = Nothing
    , cipherKeyExchange  = CipherKeyExchange_DHE_RSA
    , cipherMinVer       = Nothing
    }

-- | AES cipher (256 bit key), RSA key exchange and SHA1 for digest
cipher_AES256_SHA1 :: Cipher
cipher_AES256_SHA1 = Cipher
    { cipherID           = 0x0035
    , cipherName         = "RSA-AES256-SHA1"
    , cipherBulk         = bulk_aes256
    , cipherHash         = SHA1
    , cipherPRFHash      = Nothing
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Just SSL3
    }

-- | AES cipher (256 bit key), DHE key exchanged signed by DSA and SHA1 for digest
cipher_DHE_DSS_AES256_SHA1 :: Cipher
cipher_DHE_DSS_AES256_SHA1 = cipher_DHE_DSS_AES128_SHA1
    { cipherID           = 0x0038
    , cipherName         = "DHE-DSA-AES256-SHA1"
    , cipherBulk         = bulk_aes256
    }

-- | AES cipher (256 bit key), DHE key exchanged signed by RSA and SHA1 for digest
cipher_DHE_RSA_AES256_SHA1 :: Cipher
cipher_DHE_RSA_AES256_SHA1 = cipher_DHE_RSA_AES128_SHA1
    { cipherID           = 0x0039
    , cipherName         = "DHE-RSA-AES256-SHA1"
    , cipherBulk         = bulk_aes256
    }

-- | AES cipher (128 bit key), RSA key exchange and SHA256 for digest
cipher_AES128_SHA256 :: Cipher
cipher_AES128_SHA256 = Cipher
    { cipherID           = 0x003C
    , cipherName         = "RSA-AES128-SHA256"
    , cipherBulk         = bulk_aes128
    , cipherHash         = SHA256
    , cipherPRFHash      = Just SHA256
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Just TLS12
    }

-- | AES cipher (256 bit key), RSA key exchange and SHA256 for digest
cipher_AES256_SHA256 :: Cipher
cipher_AES256_SHA256 = Cipher
    { cipherID           = 0x003D
    , cipherName         = "RSA-AES256-SHA256"
    , cipherBulk         = bulk_aes256
    , cipherHash         = SHA256
    , cipherPRFHash      = Just SHA256
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Just TLS12
    }

-- | AESGCM cipher (128 bit key), RSA key exchange.
-- The SHA256 digest is used as a PRF, not as a MAC.
cipher_AES128GCM_SHA256 :: Cipher
cipher_AES128GCM_SHA256 = Cipher
    { cipherID           = 0x009C
    , cipherName         = "RSA-AES128GCM-SHA256"
    , cipherBulk         = bulk_aes128gcm
    , cipherHash         = SHA256
    , cipherPRFHash      = Just SHA256
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Just TLS12
    }

-- | AESGCM cipher (256 bit key), RSA key exchange.
-- The SHA384 digest is used as a PRF, not as a MAC.
cipher_AES256GCM_SHA384 :: Cipher
cipher_AES256GCM_SHA384 = Cipher
    { cipherID           = 0x009D
    , cipherName         = "RSA-AES256GCM-SHA384"
    , cipherBulk         = bulk_aes256gcm
    , cipherHash         = SHA384
    , cipherPRFHash      = Just SHA384
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Just TLS12
    }

cipher_DHE_DSS_RC4_SHA1 :: Cipher
cipher_DHE_DSS_RC4_SHA1 = cipher_DHE_DSS_AES128_SHA1
    { cipherID           = 0x0066
    , cipherName         = "DHE-DSA-RC4-SHA1"
    , cipherBulk         = bulk_rc4
    }

cipher_DHE_RSA_AES128_SHA256 :: Cipher
cipher_DHE_RSA_AES128_SHA256 = cipher_DHE_RSA_AES128_SHA1
    { cipherID           = 0x0067
    , cipherName         = "DHE-RSA-AES128-SHA256"
    , cipherHash         = SHA256
    , cipherPRFHash      = Just SHA256
    , cipherMinVer       = Just TLS12
    }

cipher_DHE_RSA_AES256_SHA256 :: Cipher
cipher_DHE_RSA_AES256_SHA256 = cipher_DHE_RSA_AES128_SHA256
    { cipherID           = 0x006B
    , cipherName         = "DHE-RSA-AES256-SHA256"
    , cipherBulk         = bulk_aes256
    }

-- | 3DES cipher (168 bit key), RSA key exchange and SHA1 for digest
cipher_RSA_3DES_EDE_CBC_SHA1 :: Cipher
cipher_RSA_3DES_EDE_CBC_SHA1 = Cipher
    { cipherID           = 0x000A
    , cipherName         = "RSA-3DES-EDE-CBC-SHA1"
    , cipherBulk         = bulk_tripledes_ede
    , cipherHash         = SHA1
    , cipherPRFHash      = Nothing
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherMinVer       = Nothing
    }

cipher_DHE_RSA_AES128GCM_SHA256 :: Cipher
cipher_DHE_RSA_AES128GCM_SHA256 = Cipher
    { cipherID           = 0x009E
    , cipherName         = "DHE-RSA-AES128GCM-SHA256"
    , cipherBulk         = bulk_aes128gcm
    , cipherHash         = SHA256
    , cipherPRFHash      = Just SHA256
    , cipherKeyExchange  = CipherKeyExchange_DHE_RSA
    , cipherMinVer       = Just TLS12 -- RFC 5288 Sec 4
    }

cipher_DHE_RSA_AES256GCM_SHA384 :: Cipher
cipher_DHE_RSA_AES256GCM_SHA384 = Cipher
    { cipherID           = 0x009F
    , cipherName         = "DHE-RSA-AES256GCM-SHA384"
    , cipherBulk         = bulk_aes256gcm
    , cipherHash         = SHA384
    , cipherPRFHash      = Just SHA384
    , cipherKeyExchange  = CipherKeyExchange_DHE_RSA
    , cipherMinVer       = Just TLS12
    }

cipher_ECDHE_ECDSA_AES128CBC_SHA :: Cipher
cipher_ECDHE_ECDSA_AES128CBC_SHA = Cipher
    { cipherID           = 0xC009
    , cipherName         = "ECDHE-ECDSA-AES128CBC-SHA"
    , cipherBulk         = bulk_aes128
    , cipherHash         = SHA1
    , cipherPRFHash      = Nothing
    , cipherKeyExchange  = CipherKeyExchange_ECDHE_ECDSA
    , cipherMinVer       = Just TLS10
    }

cipher_ECDHE_ECDSA_AES256CBC_SHA :: Cipher
cipher_ECDHE_ECDSA_AES256CBC_SHA = Cipher
    { cipherID           = 0xC00A
    , cipherName         = "ECDHE-ECDSA-AES256CBC-SHA"
    , cipherBulk         = bulk_aes256
    , cipherHash         = SHA1
    , cipherPRFHash      = Nothing
    , cipherKeyExchange  = CipherKeyExchange_ECDHE_ECDSA
    , cipherMinVer       = Just TLS10
    }

cipher_ECDHE_RSA_AES128CBC_SHA :: Cipher
cipher_ECDHE_RSA_AES128CBC_SHA = Cipher
    { cipherID           = 0xC013
    , cipherName         = "ECDHE-RSA-AES128CBC-SHA"
    , cipherBulk         = bulk_aes128
    , cipherHash         = SHA1
    , cipherPRFHash      = Nothing
    , cipherKeyExchange  = CipherKeyExchange_ECDHE_RSA
    , cipherMinVer       = Just TLS10
    }

cipher_ECDHE_RSA_AES256CBC_SHA :: Cipher
cipher_ECDHE_RSA_AES256CBC_SHA = Cipher
    { cipherID           = 0xC014
    , cipherName         = "ECDHE-RSA-AES256CBC-SHA"
    , cipherBulk         = bulk_aes256
    , cipherHash         = SHA1
    , cipherPRFHash      = Nothing
    , cipherKeyExchange  = CipherKeyExchange_ECDHE_RSA
    , cipherMinVer       = Just TLS10
    }

cipher_ECDHE_RSA_AES128CBC_SHA256 :: Cipher
cipher_ECDHE_RSA_AES128CBC_SHA256 = Cipher
    { cipherID           = 0xC027
    , cipherName         = "ECDHE-RSA-AES128CBC-SHA256"
    , cipherBulk         = bulk_aes128
    , cipherHash         = SHA256
    , cipherPRFHash      = Just SHA256
    , cipherKeyExchange  = CipherKeyExchange_ECDHE_RSA
    , cipherMinVer       = Just TLS12 -- RFC 5288 Sec 4
    }

cipher_ECDHE_RSA_AES256CBC_SHA384 :: Cipher
cipher_ECDHE_RSA_AES256CBC_SHA384 = Cipher
    { cipherID           = 0xC028
    , cipherName         = "ECDHE-RSA-AES256CBC-SHA384"
    , cipherBulk         = bulk_aes256
    , cipherHash         = SHA384
    , cipherPRFHash      = Just SHA384
    , cipherKeyExchange  = CipherKeyExchange_ECDHE_RSA
    , cipherMinVer       = Just TLS12 -- RFC 5288 Sec 4
    }

cipher_ECDHE_ECDSA_AES128CBC_SHA256 :: Cipher
cipher_ECDHE_ECDSA_AES128CBC_SHA256 = Cipher
    { cipherID           = 0xc023
    , cipherName         = "ECDHE-ECDSA-AES128CBC-SHA256"
    , cipherBulk         = bulk_aes128
    , cipherHash         = SHA256
    , cipherPRFHash      = Just SHA256
    , cipherKeyExchange  = CipherKeyExchange_ECDHE_ECDSA
    , cipherMinVer       = Just TLS12 -- RFC 5289
    }

cipher_ECDHE_ECDSA_AES256CBC_SHA384 :: Cipher
cipher_ECDHE_ECDSA_AES256CBC_SHA384 = Cipher
    { cipherID           = 0xC024
    , cipherName         = "ECDHE-ECDSA-AES256CBC-SHA384"
    , cipherBulk         = bulk_aes256
    , cipherHash         = SHA384
    , cipherPRFHash      = Just SHA384
    , cipherKeyExchange  = CipherKeyExchange_ECDHE_ECDSA
    , cipherMinVer       = Just TLS12 -- RFC 5289
    }

cipher_ECDHE_ECDSA_AES128GCM_SHA256 :: Cipher
cipher_ECDHE_ECDSA_AES128GCM_SHA256 = Cipher
    { cipherID           = 0xC02B
    , cipherName         = "ECDHE-ECDSA-AES128GCM-SHA256"
    , cipherBulk         = bulk_aes128gcm
    , cipherHash         = SHA256
    , cipherPRFHash      = Just SHA256
    , cipherKeyExchange  = CipherKeyExchange_ECDHE_ECDSA
    , cipherMinVer       = Just TLS12 -- RFC 5289
    }

cipher_ECDHE_ECDSA_AES256GCM_SHA384 :: Cipher
cipher_ECDHE_ECDSA_AES256GCM_SHA384 = Cipher
    { cipherID           = 0xC02C
    , cipherName         = "ECDHE-ECDSA-AES256GCM-SHA384"
    , cipherBulk         = bulk_aes256gcm
    , cipherHash         = SHA384
    , cipherPRFHash      = Just SHA384
    , cipherKeyExchange  = CipherKeyExchange_ECDHE_ECDSA
    , cipherMinVer       = Just TLS12 -- RFC 5289
    }

cipher_ECDHE_RSA_AES128GCM_SHA256 :: Cipher
cipher_ECDHE_RSA_AES128GCM_SHA256 = Cipher
    { cipherID           = 0xC02F
    , cipherName         = "ECDHE-RSA-AES128GCM-SHA256"
    , cipherBulk         = bulk_aes128gcm
    , cipherHash         = SHA256
    , cipherPRFHash      = Just SHA256
    , cipherKeyExchange  = CipherKeyExchange_ECDHE_RSA
    , cipherMinVer       = Just TLS12 -- RFC 5288 Sec 4
    }

cipher_ECDHE_RSA_AES256GCM_SHA384 :: Cipher
cipher_ECDHE_RSA_AES256GCM_SHA384 = Cipher
    { cipherID           = 0xC030
    , cipherName         = "ECDHE-RSA-AES256GCM-SHA384"
    , cipherBulk         = bulk_aes256gcm
    , cipherHash         = SHA384
    , cipherPRFHash      = Just SHA384
    , cipherKeyExchange  = CipherKeyExchange_ECDHE_RSA
    , cipherMinVer       = Just TLS12 -- RFC 5289
    }

-- A list of cipher suite is found from:
-- https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
