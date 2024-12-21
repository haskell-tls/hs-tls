module Network.TLS.Extra.Cipher (
    -- * Cipher suite
    ciphersuite_default,
    ciphersuite_default_det,
    ciphersuite_all,
    ciphersuite_all_det,
    ciphersuite_strong,
    ciphersuite_strong_det,
    ciphersuite_dhe_rsa,

    -- * Individual ciphers

    -- ** RFC 5288
    cipher_DHE_RSA_WITH_AES_128_GCM_SHA256,
    cipher_DHE_RSA_WITH_AES_256_GCM_SHA384,

    -- ** RFC 8446
    cipher13_AES_128_GCM_SHA256,
    cipher13_AES_256_GCM_SHA384,
    cipher13_CHACHA20_POLY1305_SHA256,
    cipher13_AES_128_CCM_SHA256,
    cipher13_TLS_AES_128_CCM_8_SHA256,

    -- ** RFC 5289
    cipher_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    cipher_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    cipher_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    cipher_ECDHE_RSA_WITH_AES_256_GCM_SHA384,

    -- ** RFC 7251
    cipher_ECDHE_ECDSA_WITH_AES_128_CCM,
    cipher_ECDHE_ECDSA_WITH_AES_256_CCM,
    cipher_ECDHE_ECDSA_WITH_AES_128_CCM_8,
    cipher_ECDHE_ECDSA_WITH_AES_256_CCM_8,

    -- ** RFC 7905
    cipher_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    cipher_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    cipher_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,

    -- * Deprecated names

    -- ** RFC 5288
    cipher_DHE_RSA_AES128GCM_SHA256,
    cipher_DHE_RSA_AES256GCM_SHA384,

    -- ** RFC 8446
    cipher_TLS13_AES128GCM_SHA256,
    cipher_TLS13_AES256GCM_SHA384,
    cipher_TLS13_CHACHA20POLY1305_SHA256,
    cipher_TLS13_AES128CCM_SHA256,
    cipher_TLS13_AES128CCM8_SHA256,

    -- ** RFC 5289
    cipher_ECDHE_ECDSA_AES128GCM_SHA256,
    cipher_ECDHE_ECDSA_AES256GCM_SHA384,
    cipher_ECDHE_RSA_AES128GCM_SHA256,
    cipher_ECDHE_RSA_AES256GCM_SHA384,

    -- ** RFC 7251
    cipher_ECDHE_ECDSA_AES128CCM_SHA256,
    cipher_ECDHE_ECDSA_AES256CCM_SHA256,
    cipher_ECDHE_ECDSA_AES128CCM8_SHA256,
    cipher_ECDHE_ECDSA_AES256CCM8_SHA256,

    -- ** RFC 7905
    cipher_ECDHE_RSA_CHACHA20POLY1305_SHA256,
    cipher_ECDHE_ECDSA_CHACHA20POLY1305_SHA256,
    cipher_DHE_RSA_CHACHA20POLY1305_SHA256,
) where

import qualified Data.ByteString as B

import Data.Tuple (swap)
import Network.TLS.Cipher
import Network.TLS.Types

import Crypto.Cipher.AES
import qualified Crypto.Cipher.ChaChaPoly1305 as ChaChaPoly1305
import Crypto.Cipher.Types hiding (Cipher, cipherName)
import Crypto.Error
import qualified Crypto.MAC.Poly1305 as Poly1305
import Crypto.System.CPU

----------------------------------------------------------------

-- | All AES and ChaCha20-Poly1305 ciphers supported ordered from strong to
-- weak.  This choice of ciphersuites should satisfy most normal needs.  For
-- otherwise strong ciphers we make little distinction between AES128 and
-- AES256, and list each but the weakest of the AES128 ciphers ahead of the
-- corresponding AES256 ciphers.
--
-- AEAD ciphers with equivalent security properties are ordered based on CPU
-- hardware-acceleration support.  If this dynamic runtime behavior is not
-- desired, use 'ciphersuite_default_det' instead.
ciphersuite_default :: [Cipher]
ciphersuite_default = ciphersuite_strong

-- | Same as 'ciphersuite_default', but using deterministic preference not
-- influenced by the CPU.
ciphersuite_default_det :: [Cipher]
ciphersuite_default_det = ciphersuite_strong_det

----------------------------------------------------------------

-- | The default ciphersuites + some not recommended last resort ciphers.
--
-- AEAD ciphers with equivalent security properties are ordered based on CPU
-- hardware-acceleration support.  If this dynamic runtime behavior is not
-- desired, use 'ciphersuite_all_det' instead.
ciphersuite_all :: [Cipher]
ciphersuite_all = ciphersuite_default ++ complement_all

-- | Same as 'ciphersuite_all', but using deterministic preference not
-- influenced by the CPU.
ciphersuite_all_det :: [Cipher]
ciphersuite_all_det = ciphersuite_default_det ++ complement_all

complement_all :: [Cipher]
complement_all =
    [ cipher_ECDHE_ECDSA_WITH_AES_128_CCM_8
    , cipher_ECDHE_ECDSA_WITH_AES_256_CCM_8
    , cipher13_TLS_AES_128_CCM_8_SHA256
    ]

-- | The strongest ciphers supported.  For ciphers with PFS, AEAD and SHA2, we
-- list each AES128 variant after the corresponding AES256 and ChaCha20-Poly1305
-- variants.  For weaker constructs, we use just the AES256 form.
--
-- AEAD ciphers with equivalent security properties are ordered based on CPU
-- hardware-acceleration support.  If this dynamic runtime behavior is not
-- desired, use 'ciphersuite_strong_det' instead.
ciphersuite_strong :: [Cipher]
ciphersuite_strong = sortOptimized sets_strong

-- | Same as 'ciphersuite_strong', but using deterministic preference not
-- influenced by the CPU.
ciphersuite_strong_det :: [Cipher]
ciphersuite_strong_det = sortDeterministic sets_strong

sets_strong :: [CipherSet]
sets_strong =
    [ -- If we have PFS + AEAD + SHA2, then allow AES128, else just 256
      SetAead
        [cipher_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384]
        [cipher_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256]
        [cipher_ECDHE_ECDSA_WITH_AES_256_CCM]
    , SetAead
        [cipher_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256]
        []
        [cipher_ECDHE_ECDSA_WITH_AES_128_CCM]
    , SetAead
        [cipher_ECDHE_RSA_WITH_AES_256_GCM_SHA384]
        [cipher_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256]
        []
    , SetAead
        [cipher_ECDHE_RSA_WITH_AES_128_GCM_SHA256]
        []
        []
    , -- TLS13 (listed at the end but version is negotiated first)
      SetAead
        [cipher13_AES_256_GCM_SHA384]
        [cipher13_CHACHA20_POLY1305_SHA256]
        []
    , SetAead
        [cipher13_AES_128_GCM_SHA256]
        []
        [cipher13_AES_128_CCM_SHA256]
    ]

-- | DHE-RSA cipher suite.  This only includes ciphers bound specifically to
-- DHE-RSA so TLS 1.3 ciphers must be added separately.
--
-- @since 2.1.5
ciphersuite_dhe_rsa :: [Cipher]
ciphersuite_dhe_rsa =
    [ cipher_DHE_RSA_WITH_AES_256_GCM_SHA384
    , cipher_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    , cipher_DHE_RSA_WITH_AES_128_GCM_SHA256
    ]

----------------------------------------------------------------
----------------------------------------------------------------

-- A list of cipher suite is found from:
-- https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4

----------------------------------------------------------------
-- RFC 5288

-- TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
cipher_DHE_RSA_WITH_AES_128_GCM_SHA256 :: Cipher
cipher_DHE_RSA_WITH_AES_128_GCM_SHA256 =
    Cipher
        { cipherID = CipherID 0x009E
        , cipherName = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
        , cipherBulk = bulk_aes128gcm
        , cipherHash = SHA256
        , cipherPRFHash = Just SHA256
        , cipherKeyExchange = CipherKeyExchange_DHE_RSA
        , cipherMinVer = Just TLS12 -- RFC 5288 Sec 4
        }

{-# DEPRECATED
    cipher_DHE_RSA_AES128GCM_SHA256
    "Use cipher_DHE_RSA_WITH_AES_128_GCM_SHA256 instead"
    #-}
cipher_DHE_RSA_AES128GCM_SHA256 :: Cipher
cipher_DHE_RSA_AES128GCM_SHA256 = cipher_DHE_RSA_WITH_AES_128_GCM_SHA256

-- TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
cipher_DHE_RSA_WITH_AES_256_GCM_SHA384 :: Cipher
cipher_DHE_RSA_WITH_AES_256_GCM_SHA384 =
    Cipher
        { cipherID = CipherID 0x009F
        , cipherName = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
        , cipherBulk = bulk_aes256gcm
        , cipherHash = SHA384
        , cipherPRFHash = Just SHA384
        , cipherKeyExchange = CipherKeyExchange_DHE_RSA
        , cipherMinVer = Just TLS12
        }

{-# DEPRECATED
    cipher_DHE_RSA_AES256GCM_SHA384
    "Use cipher_DHE_RSA_WITH_AES_256_GCM_SHA384 instead"
    #-}
cipher_DHE_RSA_AES256GCM_SHA384 :: Cipher
cipher_DHE_RSA_AES256GCM_SHA384 = cipher_DHE_RSA_WITH_AES_256_GCM_SHA384

----------------------------------------------------------------
-- RFC 8446

-- TLS_AES_128_GCM_SHA256
cipher13_AES_128_GCM_SHA256 :: Cipher
cipher13_AES_128_GCM_SHA256 =
    Cipher
        { cipherID = CipherID 0x1301
        , cipherName = "TLS_AES_128_GCM_SHA256"
        , cipherBulk = bulk_aes128gcm_13
        , cipherHash = SHA256
        , cipherPRFHash = Nothing
        , cipherKeyExchange = CipherKeyExchange_TLS13
        , cipherMinVer = Just TLS13
        }

cipher_TLS13_AES128GCM_SHA256 :: Cipher
cipher_TLS13_AES128GCM_SHA256 = cipher13_AES_128_GCM_SHA256
{-# DEPRECATED
    cipher_TLS13_AES128GCM_SHA256
    "Use cipher13_AES_128_GCM_SHA256 instead"
    #-}

-- TLS_AES_256_GCM_SHA384
cipher13_AES_256_GCM_SHA384 :: Cipher
cipher13_AES_256_GCM_SHA384 =
    Cipher
        { cipherID = CipherID 0x1302
        , cipherName = "TLS_AES_256_GCM_SHA384"
        , cipherBulk = bulk_aes256gcm_13
        , cipherHash = SHA384
        , cipherPRFHash = Nothing
        , cipherKeyExchange = CipherKeyExchange_TLS13
        , cipherMinVer = Just TLS13
        }

cipher_TLS13_AES256GCM_SHA384 :: Cipher
cipher_TLS13_AES256GCM_SHA384 = cipher13_AES_256_GCM_SHA384
{-# DEPRECATED
    cipher_TLS13_AES256GCM_SHA384
    "Use cipher13_AES_256_GCM_SHA384 instead"
    #-}

-- TLS_CHACHA20_POLY1305_SHA256
cipher13_CHACHA20_POLY1305_SHA256 :: Cipher
cipher13_CHACHA20_POLY1305_SHA256 =
    Cipher
        { cipherID = CipherID 0x1303
        , cipherName = "TLS_CHACHA20_POLY1305_SHA256"
        , cipherBulk = bulk_chacha20poly1305
        , cipherHash = SHA256
        , cipherPRFHash = Nothing
        , cipherKeyExchange = CipherKeyExchange_TLS13
        , cipherMinVer = Just TLS13
        }

cipher_TLS13_CHACHA20POLY1305_SHA256 :: Cipher
cipher_TLS13_CHACHA20POLY1305_SHA256 = cipher13_CHACHA20_POLY1305_SHA256
{-# DEPRECATED
    cipher_TLS13_CHACHA20POLY1305_SHA256
    "Use cipher13_CHACHA20_POLY1305_SHA256 instead"
    #-}

-- TLS_AES_128_CCM_SHA256
cipher13_AES_128_CCM_SHA256 :: Cipher
cipher13_AES_128_CCM_SHA256 =
    Cipher
        { cipherID = CipherID 0x1304
        , cipherName = "TLS_AES_128_CCM_SHA256"
        , cipherBulk = bulk_aes128ccm_13
        , cipherHash = SHA256
        , cipherPRFHash = Nothing
        , cipherKeyExchange = CipherKeyExchange_TLS13
        , cipherMinVer = Just TLS13
        }

cipher_TLS13_AES128CCM_SHA256 :: Cipher
cipher_TLS13_AES128CCM_SHA256 = cipher13_AES_128_CCM_SHA256
{-# DEPRECATED
    cipher_TLS13_AES128CCM_SHA256
    "Use cipher13_AES_128_CCM_SHA256 instead"
    #-}

-- TLS_AES_128_CCM_8_SHA256
cipher13_TLS_AES_128_CCM_8_SHA256 :: Cipher
cipher13_TLS_AES_128_CCM_8_SHA256 =
    Cipher
        { cipherID = CipherID 0x1305
        , cipherName = "TLS_AES_128_CCM_8_SHA256"
        , cipherBulk = bulk_aes128ccm8_13
        , cipherHash = SHA256
        , cipherPRFHash = Nothing
        , cipherKeyExchange = CipherKeyExchange_TLS13
        , cipherMinVer = Just TLS13
        }

cipher_TLS13_AES128CCM8_SHA256 :: Cipher
cipher_TLS13_AES128CCM8_SHA256 = cipher13_TLS_AES_128_CCM_8_SHA256
{-# DEPRECATED
    cipher_TLS13_AES128CCM8_SHA256
    "Use cipher13_TLS_AES_128_CCM_8_SHA256 instead"
    #-}

----------------------------------------------------------------
-- GCM: RFC 5289

-- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
cipher_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 :: Cipher
cipher_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 =
    Cipher
        { cipherID = CipherID 0xC02B
        , cipherName = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        , cipherBulk = bulk_aes128gcm
        , cipherHash = SHA256
        , cipherPRFHash = Just SHA256
        , cipherKeyExchange = CipherKeyExchange_ECDHE_ECDSA
        , cipherMinVer = Just TLS12 -- RFC 5289
        }

cipher_ECDHE_ECDSA_AES128GCM_SHA256 :: Cipher
cipher_ECDHE_ECDSA_AES128GCM_SHA256 = cipher_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
{-# DEPRECATED
    cipher_ECDHE_ECDSA_AES128GCM_SHA256
    "Use cipher_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 instead"
    #-}

-- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
cipher_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 :: Cipher
cipher_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 =
    Cipher
        { cipherID = CipherID 0xC02C
        , cipherName = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
        , cipherBulk = bulk_aes256gcm
        , cipherHash = SHA384
        , cipherPRFHash = Just SHA384
        , cipherKeyExchange = CipherKeyExchange_ECDHE_ECDSA
        , cipherMinVer = Just TLS12 -- RFC 5289
        }

cipher_ECDHE_ECDSA_AES256GCM_SHA384 :: Cipher
cipher_ECDHE_ECDSA_AES256GCM_SHA384 = cipher_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
{-# DEPRECATED
    cipher_ECDHE_ECDSA_AES256GCM_SHA384
    "Use cipher_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 instead"
    #-}

-- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
cipher_ECDHE_RSA_WITH_AES_128_GCM_SHA256 :: Cipher
cipher_ECDHE_RSA_WITH_AES_128_GCM_SHA256 =
    Cipher
        { cipherID = CipherID 0xC02F
        , cipherName = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        , cipherBulk = bulk_aes128gcm
        , cipherHash = SHA256
        , cipherPRFHash = Just SHA256
        , cipherKeyExchange = CipherKeyExchange_ECDHE_RSA
        , cipherMinVer = Just TLS12 -- RFC 5288 Sec 4
        }

cipher_ECDHE_RSA_AES128GCM_SHA256 :: Cipher
cipher_ECDHE_RSA_AES128GCM_SHA256 = cipher_ECDHE_RSA_WITH_AES_128_GCM_SHA256
{-# DEPRECATED
    cipher_ECDHE_RSA_AES128GCM_SHA256
    "Use cipher_ECDHE_RSA_WITH_AES_128_GCM_SHA256 instead"
    #-}

-- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
cipher_ECDHE_RSA_WITH_AES_256_GCM_SHA384 :: Cipher
cipher_ECDHE_RSA_WITH_AES_256_GCM_SHA384 =
    Cipher
        { cipherID = CipherID 0xC030
        , cipherName = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        , cipherBulk = bulk_aes256gcm
        , cipherHash = SHA384
        , cipherPRFHash = Just SHA384
        , cipherKeyExchange = CipherKeyExchange_ECDHE_RSA
        , cipherMinVer = Just TLS12 -- RFC 5289
        }

cipher_ECDHE_RSA_AES256GCM_SHA384 :: Cipher
cipher_ECDHE_RSA_AES256GCM_SHA384 = cipher_ECDHE_RSA_WITH_AES_256_GCM_SHA384
{-# DEPRECATED
    cipher_ECDHE_RSA_AES256GCM_SHA384
    "Use cipher_ECDHE_RSA_WITH_AES_256_GCM_SHA384 instead"
    #-}

----------------------------------------------------------------
-- CCM/ECC: RFC 7251

-- TLS_ECDHE_ECDSA_WITH_AES_128_CCM
cipher_ECDHE_ECDSA_WITH_AES_128_CCM :: Cipher
cipher_ECDHE_ECDSA_WITH_AES_128_CCM =
    Cipher
        { cipherID = CipherID 0xC0AC
        , cipherName = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"
        , cipherBulk = bulk_aes128ccm
        , cipherHash = SHA256
        , cipherPRFHash = Just SHA256
        , cipherKeyExchange = CipherKeyExchange_ECDHE_ECDSA
        , cipherMinVer = Just TLS12 -- RFC 7251
        }

cipher_ECDHE_ECDSA_AES128CCM_SHA256 :: Cipher
cipher_ECDHE_ECDSA_AES128CCM_SHA256 = cipher_ECDHE_ECDSA_WITH_AES_128_CCM
{-# DEPRECATED
    cipher_ECDHE_ECDSA_AES128CCM_SHA256
    "User cipher_ECDHE_ECDSA_WITH_AES_128_CCM instead"
    #-}

-- TLS_ECDHE_ECDSA_WITH_AES_256_CCM
cipher_ECDHE_ECDSA_WITH_AES_256_CCM :: Cipher
cipher_ECDHE_ECDSA_WITH_AES_256_CCM =
    Cipher
        { cipherID = CipherID 0xC0AD
        , cipherName = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"
        , cipherBulk = bulk_aes256ccm
        , cipherHash = SHA256
        , cipherPRFHash = Just SHA256
        , cipherKeyExchange = CipherKeyExchange_ECDHE_ECDSA
        , cipherMinVer = Just TLS12 -- RFC 7251
        }

cipher_ECDHE_ECDSA_AES256CCM_SHA256 :: Cipher
cipher_ECDHE_ECDSA_AES256CCM_SHA256 = cipher_ECDHE_ECDSA_WITH_AES_256_CCM
{-# DEPRECATED
    cipher_ECDHE_ECDSA_AES256CCM_SHA256
    "Use cipher_ECDHE_ECDSA_WITH_AES_256_CCM instead"
    #-}

-- TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
cipher_ECDHE_ECDSA_WITH_AES_128_CCM_8 :: Cipher
cipher_ECDHE_ECDSA_WITH_AES_128_CCM_8 =
    Cipher
        { cipherID = CipherID 0xC0AE
        , cipherName = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"
        , cipherBulk = bulk_aes128ccm8
        , cipherHash = SHA256
        , cipherPRFHash = Just SHA256
        , cipherKeyExchange = CipherKeyExchange_ECDHE_ECDSA
        , cipherMinVer = Just TLS12 -- RFC 7251
        }

cipher_ECDHE_ECDSA_AES128CCM8_SHA256 :: Cipher
cipher_ECDHE_ECDSA_AES128CCM8_SHA256 = cipher_ECDHE_ECDSA_WITH_AES_128_CCM_8
{-# DEPRECATED
    cipher_ECDHE_ECDSA_AES128CCM8_SHA256
    "Use cipher_ECDHE_ECDSA_WITH_AES_128_CCM_8 instead"
    #-}

-- TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
cipher_ECDHE_ECDSA_WITH_AES_256_CCM_8 :: Cipher
cipher_ECDHE_ECDSA_WITH_AES_256_CCM_8 =
    Cipher
        { cipherID = CipherID 0xC0AF
        , cipherName = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"
        , cipherBulk = bulk_aes256ccm8
        , cipherHash = SHA256
        , cipherPRFHash = Just SHA256
        , cipherKeyExchange = CipherKeyExchange_ECDHE_ECDSA
        , cipherMinVer = Just TLS12 -- RFC 7251
        }

cipher_ECDHE_ECDSA_AES256CCM8_SHA256 :: Cipher
cipher_ECDHE_ECDSA_AES256CCM8_SHA256 = cipher_ECDHE_ECDSA_WITH_AES_256_CCM_8
{-# DEPRECATED
    cipher_ECDHE_ECDSA_AES256CCM8_SHA256
    "Use cipher_ECDHE_ECDSA_WITH_AES_256_CCM_8 instead"
    #-}

----------------------------------------------------------------
-- RFC 7905

-- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
cipher_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 :: Cipher
cipher_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 =
    Cipher
        { cipherID = CipherID 0xCCA8
        , cipherName = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        , cipherBulk = bulk_chacha20poly1305
        , cipherHash = SHA256
        , cipherPRFHash = Just SHA256
        , cipherKeyExchange = CipherKeyExchange_ECDHE_RSA
        , cipherMinVer = Just TLS12
        }

cipher_ECDHE_RSA_CHACHA20POLY1305_SHA256 :: Cipher
cipher_ECDHE_RSA_CHACHA20POLY1305_SHA256 = cipher_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
{-# DEPRECATED
    cipher_ECDHE_RSA_CHACHA20POLY1305_SHA256
    "Use cipher_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 instead"
    #-}

-- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
cipher_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 :: Cipher
cipher_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 =
    Cipher
        { cipherID = CipherID 0xCCA9
        , cipherName = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
        , cipherBulk = bulk_chacha20poly1305
        , cipherHash = SHA256
        , cipherPRFHash = Just SHA256
        , cipherKeyExchange = CipherKeyExchange_ECDHE_ECDSA
        , cipherMinVer = Just TLS12
        }

cipher_ECDHE_ECDSA_CHACHA20POLY1305_SHA256 :: Cipher
cipher_ECDHE_ECDSA_CHACHA20POLY1305_SHA256 = cipher_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
{-# DEPRECATED
    cipher_ECDHE_ECDSA_CHACHA20POLY1305_SHA256
    "Use cipher_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 instead"
    #-}

-- TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
cipher_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 :: Cipher
cipher_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 =
    Cipher
        { cipherID = CipherID 0xCCAA
        , cipherName = "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        , cipherBulk = bulk_chacha20poly1305
        , cipherHash = SHA256
        , cipherPRFHash = Just SHA256
        , cipherKeyExchange = CipherKeyExchange_DHE_RSA
        , cipherMinVer = Just TLS12
        }

cipher_DHE_RSA_CHACHA20POLY1305_SHA256 :: Cipher
cipher_DHE_RSA_CHACHA20POLY1305_SHA256 = cipher_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
{-# DEPRECATED
    cipher_DHE_RSA_CHACHA20POLY1305_SHA256
    "Use cipher_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 instead"
    #-}

----------------------------------------------------------------
----------------------------------------------------------------

data CipherSet
    = SetAead [Cipher] [Cipher] [Cipher] -- gcm, chacha, ccm
    | SetOther [Cipher]

-- Preference between AEAD ciphers having equivalent properties is based on
-- hardware-acceleration support in the crypton implementation.
sortOptimized :: [CipherSet] -> [Cipher]
sortOptimized = concatMap f
  where
    f (SetAead gcm chacha ccm)
        | AESNI `notElem` processorOptions = chacha ++ gcm ++ ccm
        | PCLMUL `notElem` processorOptions = ccm ++ chacha ++ gcm
        | otherwise = gcm ++ ccm ++ chacha
    f (SetOther ciphers) = ciphers

-- Order which is deterministic but not optimized for the CPU.
sortDeterministic :: [CipherSet] -> [Cipher]
sortDeterministic = concatMap f
  where
    f (SetAead gcm chacha ccm) = gcm ++ chacha ++ ccm
    f (SetOther ciphers) = ciphers

----------------------------------------------------------------

aes128ccm :: BulkDirection -> BulkKey -> BulkAEAD
aes128ccm BulkEncrypt key =
    let ctx = noFail (cipherInit key) :: AES128
     in ( \nonce d ad ->
            let mode = AEAD_CCM (B.length d) CCM_M16 CCM_L3
                aeadIni = noFail (aeadInit mode ctx nonce)
             in swap $ aeadSimpleEncrypt aeadIni ad d 16
        )
aes128ccm BulkDecrypt key =
    let ctx = noFail (cipherInit key) :: AES128
     in ( \nonce d ad ->
            let mode = AEAD_CCM (B.length d) CCM_M16 CCM_L3
                aeadIni = noFail (aeadInit mode ctx nonce)
             in simpleDecrypt aeadIni ad d 16
        )

aes128ccm8 :: BulkDirection -> BulkKey -> BulkAEAD
aes128ccm8 BulkEncrypt key =
    let ctx = noFail (cipherInit key) :: AES128
     in ( \nonce d ad ->
            let mode = AEAD_CCM (B.length d) CCM_M8 CCM_L3
                aeadIni = noFail (aeadInit mode ctx nonce)
             in swap $ aeadSimpleEncrypt aeadIni ad d 8
        )
aes128ccm8 BulkDecrypt key =
    let ctx = noFail (cipherInit key) :: AES128
     in ( \nonce d ad ->
            let mode = AEAD_CCM (B.length d) CCM_M8 CCM_L3
                aeadIni = noFail (aeadInit mode ctx nonce)
             in simpleDecrypt aeadIni ad d 8
        )

aes128gcm :: BulkDirection -> BulkKey -> BulkAEAD
aes128gcm BulkEncrypt key =
    let ctx = noFail (cipherInit key) :: AES128
     in ( \nonce d ad ->
            let aeadIni = noFail (aeadInit AEAD_GCM ctx nonce)
             in swap $ aeadSimpleEncrypt aeadIni ad d 16
        )
aes128gcm BulkDecrypt key =
    let ctx = noFail (cipherInit key) :: AES128
     in ( \nonce d ad ->
            let aeadIni = noFail (aeadInit AEAD_GCM ctx nonce)
             in simpleDecrypt aeadIni ad d 16
        )

aes256ccm :: BulkDirection -> BulkKey -> BulkAEAD
aes256ccm BulkEncrypt key =
    let ctx = noFail (cipherInit key) :: AES256
     in ( \nonce d ad ->
            let mode = AEAD_CCM (B.length d) CCM_M16 CCM_L3
                aeadIni = noFail (aeadInit mode ctx nonce)
             in swap $ aeadSimpleEncrypt aeadIni ad d 16
        )
aes256ccm BulkDecrypt key =
    let ctx = noFail (cipherInit key) :: AES256
     in ( \nonce d ad ->
            let mode = AEAD_CCM (B.length d) CCM_M16 CCM_L3
                aeadIni = noFail (aeadInit mode ctx nonce)
             in simpleDecrypt aeadIni ad d 16
        )

aes256ccm8 :: BulkDirection -> BulkKey -> BulkAEAD
aes256ccm8 BulkEncrypt key =
    let ctx = noFail (cipherInit key) :: AES256
     in ( \nonce d ad ->
            let mode = AEAD_CCM (B.length d) CCM_M8 CCM_L3
                aeadIni = noFail (aeadInit mode ctx nonce)
             in swap $ aeadSimpleEncrypt aeadIni ad d 8
        )
aes256ccm8 BulkDecrypt key =
    let ctx = noFail (cipherInit key) :: AES256
     in ( \nonce d ad ->
            let mode = AEAD_CCM (B.length d) CCM_M8 CCM_L3
                aeadIni = noFail (aeadInit mode ctx nonce)
             in simpleDecrypt aeadIni ad d 8
        )

aes256gcm :: BulkDirection -> BulkKey -> BulkAEAD
aes256gcm BulkEncrypt key =
    let ctx = noFail (cipherInit key) :: AES256
     in ( \nonce d ad ->
            let aeadIni = noFail (aeadInit AEAD_GCM ctx nonce)
             in swap $ aeadSimpleEncrypt aeadIni ad d 16
        )
aes256gcm BulkDecrypt key =
    let ctx = noFail (cipherInit key) :: AES256
     in ( \nonce d ad ->
            let aeadIni = noFail (aeadInit AEAD_GCM ctx nonce)
             in simpleDecrypt aeadIni ad d 16
        )

simpleDecrypt
    :: AEAD cipher -> B.ByteString -> B.ByteString -> Int -> (B.ByteString, AuthTag)
simpleDecrypt aeadIni header input taglen = (output, tag)
  where
    aead = aeadAppendHeader aeadIni header
    (output, aeadFinal) = aeadDecrypt aead input
    tag = aeadFinalize aeadFinal taglen

noFail :: CryptoFailable a -> a
noFail = throwCryptoError

chacha20poly1305 :: BulkDirection -> BulkKey -> BulkAEAD
chacha20poly1305 BulkEncrypt key nonce =
    let st = noFail (ChaChaPoly1305.nonce12 nonce >>= ChaChaPoly1305.initialize key)
     in ( \input ad ->
            let st2 = ChaChaPoly1305.finalizeAAD (ChaChaPoly1305.appendAAD ad st)
                (output, st3) = ChaChaPoly1305.encrypt input st2
                Poly1305.Auth tag = ChaChaPoly1305.finalize st3
             in (output, AuthTag tag)
        )
chacha20poly1305 BulkDecrypt key nonce =
    let st = noFail (ChaChaPoly1305.nonce12 nonce >>= ChaChaPoly1305.initialize key)
     in ( \input ad ->
            let st2 = ChaChaPoly1305.finalizeAAD (ChaChaPoly1305.appendAAD ad st)
                (output, st3) = ChaChaPoly1305.decrypt input st2
                Poly1305.Auth tag = ChaChaPoly1305.finalize st3
             in (output, AuthTag tag)
        )

----------------------------------------------------------------

bulk_aes128ccm :: Bulk
bulk_aes128ccm =
    Bulk
        { bulkName = "AES128CCM"
        , bulkKeySize = 16 -- RFC 5116 Sec 5.1: K_LEN
        , bulkIVSize = 4 -- RFC 6655 CCMNonce.salt, fixed_iv_length
        , bulkExplicitIV = 8
        , bulkAuthTagLen = 16
        , bulkBlockSize = 0 -- dummy, not used
        , bulkF = BulkAeadF aes128ccm
        }

bulk_aes128ccm8 :: Bulk
bulk_aes128ccm8 =
    Bulk
        { bulkName = "AES128CCM8"
        , bulkKeySize = 16 -- RFC 5116 Sec 5.1: K_LEN
        , bulkIVSize = 4 -- RFC 6655 CCMNonce.salt, fixed_iv_length
        , bulkExplicitIV = 8
        , bulkAuthTagLen = 8
        , bulkBlockSize = 0 -- dummy, not used
        , bulkF = BulkAeadF aes128ccm8
        }

bulk_aes128gcm :: Bulk
bulk_aes128gcm =
    Bulk
        { bulkName = "AES128GCM"
        , bulkKeySize = 16 -- RFC 5116 Sec 5.1: K_LEN
        , bulkIVSize = 4 -- RFC 5288 GCMNonce.salt, fixed_iv_length
        , bulkExplicitIV = 8
        , bulkAuthTagLen = 16
        , bulkBlockSize = 0 -- dummy, not used
        , bulkF = BulkAeadF aes128gcm
        }

bulk_aes256ccm :: Bulk
bulk_aes256ccm =
    Bulk
        { bulkName = "AES256CCM"
        , bulkKeySize = 32 -- RFC 5116 Sec 5.1: K_LEN
        , bulkIVSize = 4 -- RFC 6655 CCMNonce.salt, fixed_iv_length
        , bulkExplicitIV = 8
        , bulkAuthTagLen = 16
        , bulkBlockSize = 0 -- dummy, not used
        , bulkF = BulkAeadF aes256ccm
        }

bulk_aes256ccm8 :: Bulk
bulk_aes256ccm8 =
    Bulk
        { bulkName = "AES256CCM8"
        , bulkKeySize = 32 -- RFC 5116 Sec 5.1: K_LEN
        , bulkIVSize = 4 -- RFC 6655 CCMNonce.salt, fixed_iv_length
        , bulkExplicitIV = 8
        , bulkAuthTagLen = 8
        , bulkBlockSize = 0 -- dummy, not used
        , bulkF = BulkAeadF aes256ccm8
        }

bulk_aes256gcm :: Bulk
bulk_aes256gcm =
    Bulk
        { bulkName = "AES256GCM"
        , bulkKeySize = 32 -- RFC 5116 Sec 5.1: K_LEN
        , bulkIVSize = 4 -- RFC 5288 GCMNonce.salt, fixed_iv_length
        , bulkExplicitIV = 8
        , bulkAuthTagLen = 16
        , bulkBlockSize = 0 -- dummy, not used
        , bulkF = BulkAeadF aes256gcm
        }

bulk_chacha20poly1305 :: Bulk
bulk_chacha20poly1305 =
    Bulk
        { bulkName = "CHACHA20POLY1305"
        , bulkKeySize = 32
        , bulkIVSize = 12 -- RFC 7905 section 2, fixed_iv_length
        , bulkExplicitIV = 0
        , bulkAuthTagLen = 16
        , bulkBlockSize = 0 -- dummy, not used
        , bulkF = BulkAeadF chacha20poly1305
        }

-- TLS13 bulks are same as TLS12 except they never have explicit IV
bulk_aes128gcm_13 :: Bulk
bulk_aes128gcm_13 = bulk_aes128gcm{bulkIVSize = 12, bulkExplicitIV = 0}

bulk_aes256gcm_13 :: Bulk
bulk_aes256gcm_13 = bulk_aes256gcm{bulkIVSize = 12, bulkExplicitIV = 0}

bulk_aes128ccm_13 :: Bulk
bulk_aes128ccm_13 = bulk_aes128ccm{bulkIVSize = 12, bulkExplicitIV = 0}

bulk_aes128ccm8_13 :: Bulk
bulk_aes128ccm8_13 = bulk_aes128ccm8{bulkIVSize = 12, bulkExplicitIV = 0}
