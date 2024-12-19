{-# LANGUAGE PatternSynonyms #-}

module Network.TLS.HashAndSignature (
    HashAlgorithm (
        ..,
        HashNone,
        HashMD5,
        HashSHA1,
        HashSHA224,
        HashSHA256,
        HashSHA384,
        HashSHA512,
        HashIntrinsic
    ),
    SignatureAlgorithm (
        ..,
        SignatureAnonymous,
        SignatureRSA,
        SignatureDSA,
        SignatureECDSA,
        SignatureRSApssRSAeSHA256,
        SignatureRSApssRSAeSHA384,
        SignatureRSApssRSAeSHA512,
        SignatureEd25519,
        SignatureEd448,
        SignatureRSApsspssSHA256,
        SignatureRSApsspssSHA384,
        SignatureRSApsspssSHA512
    ),
    HashAndSignatureAlgorithm,
    supportedSignatureSchemes,
) where

import Network.TLS.Imports

------------------------------------------------------------

newtype HashAlgorithm = HashAlgorithm {fromHashAlgorithm :: Word8}
    deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern HashNone      :: HashAlgorithm
pattern HashNone       = HashAlgorithm 0
pattern HashMD5       :: HashAlgorithm
pattern HashMD5        = HashAlgorithm 1
pattern HashSHA1      :: HashAlgorithm
pattern HashSHA1       = HashAlgorithm 2
pattern HashSHA224    :: HashAlgorithm
pattern HashSHA224     = HashAlgorithm 3
pattern HashSHA256    :: HashAlgorithm
pattern HashSHA256     = HashAlgorithm 4
pattern HashSHA384    :: HashAlgorithm
pattern HashSHA384     = HashAlgorithm 5
pattern HashSHA512    :: HashAlgorithm
pattern HashSHA512     = HashAlgorithm 6
pattern HashIntrinsic :: HashAlgorithm
pattern HashIntrinsic  = HashAlgorithm 8

instance Show HashAlgorithm where
    show HashNone          = "None"
    show HashMD5           = "MD5"
    show HashSHA1          = "SHA1"
    show HashSHA224        = "SHA224"
    show HashSHA256        = "SHA256"
    show HashSHA384        = "SHA384"
    show HashSHA512        = "SHA512"
    show HashIntrinsic     = "TLS13"
    show (HashAlgorithm x) = "Hash " ++ show x
{- FOURMOLU_ENABLE -}

------------------------------------------------------------

newtype SignatureAlgorithm = SignatureAlgorithm {fromSignatureAlgorithm :: Word8}
    deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern SignatureAnonymous        :: SignatureAlgorithm
pattern SignatureAnonymous         = SignatureAlgorithm 0
pattern SignatureRSA              :: SignatureAlgorithm
pattern SignatureRSA               = SignatureAlgorithm 1
pattern SignatureDSA              :: SignatureAlgorithm
pattern SignatureDSA               = SignatureAlgorithm 2
pattern SignatureECDSA            :: SignatureAlgorithm
pattern SignatureECDSA             = SignatureAlgorithm 3
-- TLS 1.3 from here
pattern SignatureRSApssRSAeSHA256 :: SignatureAlgorithm
pattern SignatureRSApssRSAeSHA256  = SignatureAlgorithm 4
pattern SignatureRSApssRSAeSHA384 :: SignatureAlgorithm
pattern SignatureRSApssRSAeSHA384  = SignatureAlgorithm 5
pattern SignatureRSApssRSAeSHA512 :: SignatureAlgorithm
pattern SignatureRSApssRSAeSHA512  = SignatureAlgorithm 6
pattern SignatureEd25519          :: SignatureAlgorithm
pattern SignatureEd25519           = SignatureAlgorithm 7
pattern SignatureEd448            :: SignatureAlgorithm
pattern SignatureEd448             = SignatureAlgorithm 8
pattern SignatureRSApsspssSHA256  :: SignatureAlgorithm
pattern SignatureRSApsspssSHA256   = SignatureAlgorithm 9
pattern SignatureRSApsspssSHA384  :: SignatureAlgorithm
pattern SignatureRSApsspssSHA384   = SignatureAlgorithm 10
pattern SignatureRSApsspssSHA512  :: SignatureAlgorithm
pattern SignatureRSApsspssSHA512   = SignatureAlgorithm 11

instance Show SignatureAlgorithm where
    show SignatureAnonymous        = "Anonymous"
    show SignatureRSA              = "RSA"
    show SignatureDSA              = "DSA"
    show SignatureECDSA            = "ECDSA"
    show SignatureRSApssRSAeSHA256 = "RSApssRSAeSHA256"
    show SignatureRSApssRSAeSHA384 = "RSApssRSAeSHA384"
    show SignatureRSApssRSAeSHA512 = "RSApssRSAeSHA512"
    show SignatureEd25519          = "Ed25519"
    show SignatureEd448            = "Ed448"
    show SignatureRSApsspssSHA256  = "RSApsspssSHA256"
    show SignatureRSApsspssSHA384  = "RSApsspssSHA384"
    show SignatureRSApsspssSHA512  = "RSApsspssSHA512"
    show (SignatureAlgorithm x)    = "Signature " ++ show x
{- FOURMOLU_ENABLE -}

------------------------------------------------------------

type HashAndSignatureAlgorithm = (HashAlgorithm, SignatureAlgorithm)

{- FOURMOLU_DISABLE -}
supportedSignatureSchemes :: [HashAndSignatureAlgorithm]
supportedSignatureSchemes =
    -- EdDSA algorithms
    [ (HashIntrinsic, SignatureEd448)   -- ed448  (0x0808)
    , (HashIntrinsic, SignatureEd25519) -- ed25519(0x0807)
    -- ECDSA algorithms
    , (HashSHA256,    SignatureECDSA)   -- ecdsa_secp256r1_sha256(0x0403)
    , (HashSHA384,    SignatureECDSA)   -- ecdsa_secp384r1_sha384(0x0503)
    , (HashSHA512,    SignatureECDSA)   -- ecdsa_secp256r1_sha256(0x0403)
    -- RSASSA-PSS algorithms with public key OID RSASSA-PSS
    , (HashIntrinsic, SignatureRSApssRSAeSHA512) -- rsa_pss_pss_sha512(0x080b)
    , (HashIntrinsic, SignatureRSApssRSAeSHA384) -- rsa_pss_pss_sha384(0x080a)
    , (HashIntrinsic, SignatureRSApssRSAeSHA256) -- rsa_pss_pss_sha256(0x0809)
    -- RSASSA-PKCS1-v1_5 algorithms
    , (HashSHA512,    SignatureRSA)    -- rsa_pkcs1_sha512(0x0601)
    , (HashSHA384,    SignatureRSA)    -- rsa_pkcs1_sha384(0x0501)
    , (HashSHA256,    SignatureRSA)    -- rsa_pkcs1_sha256(0x0401)
    -- Legacy algorithms
    , (HashSHA1,      SignatureRSA)    -- rsa_pkcs1_sha1  (0x0201)
    , (HashSHA1,      SignatureECDSA)  -- ecdsa_sha1      (0x0203)
    ]
{- FOURMOLU_ENABLE -}
