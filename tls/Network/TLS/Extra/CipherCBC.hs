module Network.TLS.Extra.CipherCBC (
    -- * TLS 1.2 CBC ciphers with PFS and SHA2
    ciphersuite_pfs_sha2_cbc,
    ciphersuite_ecdhe_sha2_cbc,
    ciphersuite_dhe_rsa_sha2_cbc,

    -- ** Individual CBC ciphers
    cipher_DHE_RSA_AES128_SHA256,
    cipher_DHE_RSA_AES256_SHA256,
    cipher_ECDHE_RSA_AES128CBC_SHA256,
    cipher_ECDHE_RSA_AES256CBC_SHA384,
    cipher_ECDHE_ECDSA_AES128CBC_SHA256,
) where

import Crypto.Cipher.AES
import Crypto.Cipher.Types hiding (Cipher, cipherName)
import Crypto.Error
-- import Crypto.System.CPU
import qualified Data.ByteString as B

import Network.TLS.Cipher
import Network.TLS.Imports
import Network.TLS.Types hiding (IV)

----------------------------------------------------------------

-- | TLS 1.2 AES CBC ciphers with DHE or ECDHE key exchange, ECDSA or RSA
-- authentication and a SHA256 or SHA2384 MAC.
-- For legacy applications only, deprecated in HTTPS.
ciphersuite_pfs_sha2_cbc :: [Cipher]
ciphersuite_pfs_sha2_cbc =
    [ cipher_ECDHE_ECDSA_AES128CBC_SHA256
    , cipher_ECDHE_ECDSA_AES256CBC_SHA384
    , cipher_ECDHE_RSA_AES128CBC_SHA256
    , cipher_ECDHE_RSA_AES256CBC_SHA384
    , cipher_DHE_RSA_AES128_SHA256
    , cipher_DHE_RSA_AES256_SHA256
    ]

-- | TLS 1.2 AES CBC ciphers with ECDHE key exchange, ECDSA or RSA
-- authentication and a SHA256 or SHA2384 MAC.
-- For legacy applications only, deprecated in HTTPS.
ciphersuite_ecdhe_sha2_cbc :: [Cipher]
ciphersuite_ecdhe_sha2_cbc =
    [ cipher_ECDHE_ECDSA_AES128CBC_SHA256
    , cipher_ECDHE_ECDSA_AES256CBC_SHA384
    , cipher_ECDHE_RSA_AES128CBC_SHA256
    , cipher_ECDHE_RSA_AES256CBC_SHA384
    ]

-- | TLS 1.2 AES CBC ciphers with DHE key exchange, RSA authentication and a
-- SHA256 MAC.
-- For legacy applications only, deprecated in HTTPS.
ciphersuite_dhe_rsa_sha2_cbc :: [Cipher]
ciphersuite_dhe_rsa_sha2_cbc =
    [ cipher_DHE_RSA_AES256_SHA256
    , cipher_DHE_RSA_AES128_SHA256
    ]

----------------------------------------------------------------

-- | TLS 1.2 AES128 CBC, with DHE key exchange, RSA authentication and a SHA256 MAC.
-- For legacy applications only, deprecated in HTTPS.
cipher_DHE_RSA_AES128_SHA256 :: Cipher
cipher_DHE_RSA_AES128_SHA256 =
    Cipher
        { cipherID = 0x0067
        , cipherName = "DHE-RSA-AES128-SHA256"
        , cipherBulk = bulk_aes128
        , cipherHash = SHA256
        , cipherPRFHash = Just SHA256
        , cipherKeyExchange = CipherKeyExchange_DHE_RSA
        , cipherMinVer = Just TLS12 -- RFC 5288 Sec 4
        }

-- | TLS 1.2 AES256 CBC, with DHE key exchange, RSA authentication and a SHA256 MAC.
-- For legacy applications only, deprecated in HTTPS.
cipher_DHE_RSA_AES256_SHA256 :: Cipher
cipher_DHE_RSA_AES256_SHA256 =
    cipher_DHE_RSA_AES128_SHA256
        { cipherID = 0x006B
        , cipherName = "DHE-RSA-AES256-SHA256"
        , cipherBulk = bulk_aes256
        }

-- | TLS 1.2 AES128 CBC, with ECDHE key exchange, RSA authentication and a SHA256 MAC.
-- For legacy applications only, deprecated in HTTPS.
cipher_ECDHE_RSA_AES128CBC_SHA256 :: Cipher
cipher_ECDHE_RSA_AES128CBC_SHA256 =
    Cipher
        { cipherID = 0xC027
        , cipherName = "ECDHE-RSA-AES128CBC-SHA256"
        , cipherBulk = bulk_aes128
        , cipherHash = SHA256
        , cipherPRFHash = Just SHA256
        , cipherKeyExchange = CipherKeyExchange_ECDHE_RSA
        , cipherMinVer = Just TLS12 -- RFC 5288 Sec 4
        }

-- | TLS 1.2 AES256 CBC, with ECDHE key exchange, RSA authentication and a SHA384 MAC.
-- For legacy applications only, deprecated in HTTPS.
cipher_ECDHE_RSA_AES256CBC_SHA384 :: Cipher
cipher_ECDHE_RSA_AES256CBC_SHA384 =
    Cipher
        { cipherID = 0xC028
        , cipherName = "ECDHE-RSA-AES256CBC-SHA384"
        , cipherBulk = bulk_aes256
        , cipherHash = SHA384
        , cipherPRFHash = Just SHA384
        , cipherKeyExchange = CipherKeyExchange_ECDHE_RSA
        , cipherMinVer = Just TLS12 -- RFC 5288 Sec 4
        }

-- | TLS 1.2 AES128 CBC, with ECDHE key exchange, ECDSA authentication and a SHA256 MAC.
-- For legacy applications only, deprecated in HTTPS.
cipher_ECDHE_ECDSA_AES128CBC_SHA256 :: Cipher
cipher_ECDHE_ECDSA_AES128CBC_SHA256 =
    Cipher
        { cipherID = 0xc023
        , cipherName = "ECDHE-ECDSA-AES128CBC-SHA256"
        , cipherBulk = bulk_aes128
        , cipherHash = SHA256
        , cipherPRFHash = Just SHA256
        , cipherKeyExchange = CipherKeyExchange_ECDHE_ECDSA
        , cipherMinVer = Just TLS12 -- RFC 5289
        }

-- | TLS 1.2 AES256 CBC, with ECDHE key exchange, ECDSA authentication and a SHA384 MAC.
-- For legacy applications only, deprecated in HTTPS.
cipher_ECDHE_ECDSA_AES256CBC_SHA384 :: Cipher
cipher_ECDHE_ECDSA_AES256CBC_SHA384 =
    Cipher
        { cipherID = 0xC024
        , cipherName = "ECDHE-ECDSA-AES256CBC-SHA384"
        , cipherBulk = bulk_aes256
        , cipherHash = SHA384
        , cipherPRFHash = Just SHA384
        , cipherKeyExchange = CipherKeyExchange_ECDHE_ECDSA
        , cipherMinVer = Just TLS12 -- RFC 5289
        }

----------------------------------------------------------------

aes128cbc :: BulkDirection -> BulkKey -> BulkBlock
aes128cbc BulkEncrypt key =
    let ctx = noFail (cipherInit key) :: AES128
     in ( \iv input ->
            let output = cbcEncrypt ctx (makeIV_ iv) input in (output, takelast 16 output)
        )
aes128cbc BulkDecrypt key =
    let ctx = noFail (cipherInit key) :: AES128
     in ( \iv input ->
            let output = cbcDecrypt ctx (makeIV_ iv) input in (output, takelast 16 input)
        )

aes256cbc :: BulkDirection -> BulkKey -> BulkBlock
aes256cbc BulkEncrypt key =
    let ctx = noFail (cipherInit key) :: AES256
     in ( \iv input ->
            let output = cbcEncrypt ctx (makeIV_ iv) input in (output, takelast 16 output)
        )
aes256cbc BulkDecrypt key =
    let ctx = noFail (cipherInit key) :: AES256
     in ( \iv input ->
            let output = cbcDecrypt ctx (makeIV_ iv) input in (output, takelast 16 input)
        )

makeIV_ :: BlockCipher a => B.ByteString -> IV a
makeIV_ = fromMaybe (error "makeIV_") . makeIV

takelast :: Int -> B.ByteString -> B.ByteString
takelast i b = B.drop (B.length b - i) b

noFail :: CryptoFailable a -> a
noFail = throwCryptoError

----------------------------------------------------------------

bulk_aes128 :: Bulk
bulk_aes128 =
    Bulk
        { bulkName = "AES128"
        , bulkKeySize = 16
        , bulkIVSize = 16
        , bulkExplicitIV = 0
        , bulkAuthTagLen = 0
        , bulkBlockSize = 16
        , bulkF = BulkBlockF aes128cbc
        }

bulk_aes256 :: Bulk
bulk_aes256 =
    Bulk
        { bulkName = "AES256"
        , bulkKeySize = 32
        , bulkIVSize = 16
        , bulkExplicitIV = 0
        , bulkAuthTagLen = 0
        , bulkBlockSize = 16
        , bulkF = BulkBlockF aes256cbc
        }
