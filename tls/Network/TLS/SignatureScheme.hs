{-# LANGUAGE PatternSynonyms #-}

-- | TLS signature schemes, as RFC 8446 section 4.2.3 and the IANA
-- TLS SignatureScheme registry name them.
module Network.TLS.SignatureScheme (
    SignatureScheme (
        ..,
        -- the schemes the IANA registry names
        RSA_PKCS1_SHA1,
        ECDSA_SHA1,
        DSA_SHA1,
        RSA_PKCS1_SHA256,
        ECDSA_SECP256R1_SHA256,
        RSA_PKCS1_SHA384,
        ECDSA_SECP384R1_SHA384,
        RSA_PKCS1_SHA512,
        ECDSA_SECP521R1_SHA512,
        RSA_PSS_RSAE_SHA256,
        RSA_PSS_RSAE_SHA384,
        RSA_PSS_RSAE_SHA512,
        ED25519,
        ED448,
        RSA_PSS_PSS_SHA256,
        RSA_PSS_PSS_SHA384,
        RSA_PSS_PSS_SHA512,
        ECDSA_BRAINPOOLP256R1TLS13_SHA256,
        ECDSA_BRAINPOOLP384R1TLS13_SHA384,
        ECDSA_BRAINPOOLP512R1TLS13_SHA512,
        MLDSA44,
        MLDSA65,
        MLDSA87,

        -- the TLS 1.2 combinations it does not
        RSA_PKCS1_MD5,
        DSA_MD5,
        ECDSA_MD5,
        RSA_PKCS1_SHA224,
        DSA_SHA224,
        ECDSA_SHA224,
        DSA_SHA256,
        DSA_SHA384,
        DSA_SHA512
    ),
    supportedSignatureSchemes,
    signatureSchemesForTLS13,
    isMLDSA,
    rsaPkcs1Schemes,
    rsaPssSchemes,
    dsaSchemes,
    ecdsaSchemes,
) where

import Numeric (showHex)

import Network.TLS.Imports

-- | A signature scheme: the 16-bit number that travels on the wire, with a
-- name for each one this library knows.
--
-- A scheme is one number, not a hash and a signature algorithm.  TLS 1.2
-- read the two bytes separately and some of the values still line up that
-- way, but from TLS 1.3 the number is indivisible, and for ML-DSA neither
-- byte means what it does elsewhere -- 0x09 is no hash, and the second byte
-- repeats numbers RSASSA-PSS uses, so @mldsa87@ read byte by byte looks
-- like @rsa_pss_rsae_sha512@.  Code that took the halves apart got that
-- wrong, which is why the halves are gone.
--
-- The names are pattern synonyms with no @COMPLETE@ pragma, so a @case@
-- over them needs a catch-all and a scheme named in a later release breaks
-- nothing that compiled against this one.  'Show' is written out for the
-- same reason: a program built against an older hs-tls still says something
-- useful about a scheme a newer one produced.
newtype SignatureScheme = SignatureScheme {fromSignatureScheme :: Word16}
    deriving (Eq, Ord)

{- FOURMOLU_DISABLE -}
pattern RSA_PKCS1_SHA1                    :: SignatureScheme
pattern RSA_PKCS1_SHA1                     = SignatureScheme 0x0201  -- RFC8446, legacy
pattern ECDSA_SHA1                        :: SignatureScheme
pattern ECDSA_SHA1                         = SignatureScheme 0x0203  -- RFC8446, legacy
pattern DSA_SHA1                          :: SignatureScheme
pattern DSA_SHA1                           = SignatureScheme 0x0202  -- TLS 1.2 only, no IANA name
pattern RSA_PKCS1_SHA256                  :: SignatureScheme
pattern RSA_PKCS1_SHA256                   = SignatureScheme 0x0401
pattern ECDSA_SECP256R1_SHA256            :: SignatureScheme
pattern ECDSA_SECP256R1_SHA256             = SignatureScheme 0x0403
pattern RSA_PKCS1_SHA384                  :: SignatureScheme
pattern RSA_PKCS1_SHA384                   = SignatureScheme 0x0501
pattern ECDSA_SECP384R1_SHA384            :: SignatureScheme
pattern ECDSA_SECP384R1_SHA384             = SignatureScheme 0x0503
pattern RSA_PKCS1_SHA512                  :: SignatureScheme
pattern RSA_PKCS1_SHA512                   = SignatureScheme 0x0601
pattern ECDSA_SECP521R1_SHA512            :: SignatureScheme
pattern ECDSA_SECP521R1_SHA512             = SignatureScheme 0x0603
pattern RSA_PSS_RSAE_SHA256               :: SignatureScheme
pattern RSA_PSS_RSAE_SHA256                = SignatureScheme 0x0804
pattern RSA_PSS_RSAE_SHA384               :: SignatureScheme
pattern RSA_PSS_RSAE_SHA384                = SignatureScheme 0x0805
pattern RSA_PSS_RSAE_SHA512               :: SignatureScheme
pattern RSA_PSS_RSAE_SHA512                = SignatureScheme 0x0806
pattern ED25519                           :: SignatureScheme
pattern ED25519                            = SignatureScheme 0x0807
pattern ED448                             :: SignatureScheme
pattern ED448                              = SignatureScheme 0x0808
pattern RSA_PSS_PSS_SHA256                :: SignatureScheme
pattern RSA_PSS_PSS_SHA256                 = SignatureScheme 0x0809
pattern RSA_PSS_PSS_SHA384                :: SignatureScheme
pattern RSA_PSS_PSS_SHA384                 = SignatureScheme 0x080a
pattern RSA_PSS_PSS_SHA512                :: SignatureScheme
pattern RSA_PSS_PSS_SHA512                 = SignatureScheme 0x080b
pattern ECDSA_BRAINPOOLP256R1TLS13_SHA256 :: SignatureScheme
pattern ECDSA_BRAINPOOLP256R1TLS13_SHA256  = SignatureScheme 0x081a  -- RFC8734
pattern ECDSA_BRAINPOOLP384R1TLS13_SHA384 :: SignatureScheme
pattern ECDSA_BRAINPOOLP384R1TLS13_SHA384  = SignatureScheme 0x081b  -- RFC8734
pattern ECDSA_BRAINPOOLP512R1TLS13_SHA512 :: SignatureScheme
pattern ECDSA_BRAINPOOLP512R1TLS13_SHA512  = SignatureScheme 0x081c  -- RFC8734
pattern MLDSA44                           :: SignatureScheme
pattern MLDSA44                            = SignatureScheme 0x0904  -- draft-ietf-tls-mldsa
pattern MLDSA65                           :: SignatureScheme
pattern MLDSA65                            = SignatureScheme 0x0905  -- draft-ietf-tls-mldsa
pattern MLDSA87                           :: SignatureScheme
pattern MLDSA87                            = SignatureScheme 0x0906  -- draft-ietf-tls-mldsa

-- TLS 1.2 wrote a hash and a signature algorithm, and some of the
-- combinations it allowed are schemes the registry never named.  They still
-- turn up: a certificate can be signed with one, and the peer's
-- signature_algorithms list is matched against the number.
pattern RSA_PKCS1_MD5                      :: SignatureScheme
pattern RSA_PKCS1_MD5                       = SignatureScheme 0x0101
pattern DSA_MD5                            :: SignatureScheme
pattern DSA_MD5                             = SignatureScheme 0x0102
pattern ECDSA_MD5                          :: SignatureScheme
pattern ECDSA_MD5                           = SignatureScheme 0x0103
pattern RSA_PKCS1_SHA224                   :: SignatureScheme
pattern RSA_PKCS1_SHA224                    = SignatureScheme 0x0301
pattern DSA_SHA224                         :: SignatureScheme
pattern DSA_SHA224                          = SignatureScheme 0x0302
pattern ECDSA_SHA224                       :: SignatureScheme
pattern ECDSA_SHA224                        = SignatureScheme 0x0303
pattern DSA_SHA256                         :: SignatureScheme
pattern DSA_SHA256                          = SignatureScheme 0x0402
pattern DSA_SHA384                         :: SignatureScheme
pattern DSA_SHA384                          = SignatureScheme 0x0502
pattern DSA_SHA512                         :: SignatureScheme
pattern DSA_SHA512                          = SignatureScheme 0x0602

-- | The IANA name, and the number for a scheme this release does not know.
instance Show SignatureScheme where
    show RSA_PKCS1_SHA1                    = "rsa_pkcs1_sha1"
    show ECDSA_SHA1                        = "ecdsa_sha1"
    show DSA_SHA1                          = "dsa_sha1"
    show RSA_PKCS1_SHA256                  = "rsa_pkcs1_sha256"
    show ECDSA_SECP256R1_SHA256            = "ecdsa_secp256r1_sha256"
    show RSA_PKCS1_SHA384                  = "rsa_pkcs1_sha384"
    show ECDSA_SECP384R1_SHA384            = "ecdsa_secp384r1_sha384"
    show RSA_PKCS1_SHA512                  = "rsa_pkcs1_sha512"
    show ECDSA_SECP521R1_SHA512            = "ecdsa_secp521r1_sha512"
    show RSA_PSS_RSAE_SHA256               = "rsa_pss_rsae_sha256"
    show RSA_PSS_RSAE_SHA384               = "rsa_pss_rsae_sha384"
    show RSA_PSS_RSAE_SHA512               = "rsa_pss_rsae_sha512"
    show ED25519                           = "ed25519"
    show ED448                             = "ed448"
    show RSA_PSS_PSS_SHA256                = "rsa_pss_pss_sha256"
    show RSA_PSS_PSS_SHA384                = "rsa_pss_pss_sha384"
    show RSA_PSS_PSS_SHA512                = "rsa_pss_pss_sha512"
    show ECDSA_BRAINPOOLP256R1TLS13_SHA256 = "ecdsa_brainpoolP256r1tls13_sha256"
    show ECDSA_BRAINPOOLP384R1TLS13_SHA384 = "ecdsa_brainpoolP384r1tls13_sha384"
    show ECDSA_BRAINPOOLP512R1TLS13_SHA512 = "ecdsa_brainpoolP512r1tls13_sha512"
    show MLDSA44                           = "mldsa44"
    show MLDSA65                           = "mldsa65"
    show MLDSA87                           = "mldsa87"
    show RSA_PKCS1_MD5                      = "rsa_pkcs1_md5"
    show DSA_MD5                            = "dsa_md5"
    show ECDSA_MD5                          = "ecdsa_md5"
    show RSA_PKCS1_SHA224                   = "rsa_pkcs1_sha224"
    show DSA_SHA224                         = "dsa_sha224"
    show ECDSA_SHA224                       = "ecdsa_sha224"
    show DSA_SHA256                         = "dsa_sha256"
    show DSA_SHA384                         = "dsa_sha384"
    show DSA_SHA512                         = "dsa_sha512"
    show (SignatureScheme n) = "signature_scheme(0x" ++ hex4 n ++ ")"
{- FOURMOLU_ENABLE -}

-- | Four hexadecimal digits, as the IANA registry writes a code point.
hex4 :: Word16 -> String
hex4 n = replicate (4 - length digits) '0' ++ digits
  where
    digits = showHex n ""

-- | Is this one of the ML-DSA schemes?  They are TLS 1.3 only, so the
-- TLS 1.2 paths filter them out and refuse one that arrives anyway.
isMLDSA :: SignatureScheme -> Bool
isMLDSA MLDSA44 = True
isMLDSA MLDSA65 = True
isMLDSA MLDSA87 = True
isMLDSA _ = False

{- FOURMOLU_DISABLE -}
-- | The schemes an RSA key signs under with PKCS#1 v1.5.
rsaPkcs1Schemes :: [SignatureScheme]
rsaPkcs1Schemes =
    [ RSA_PKCS1_MD5
    , RSA_PKCS1_SHA1
    , RSA_PKCS1_SHA224
    , RSA_PKCS1_SHA256
    , RSA_PKCS1_SHA384
    , RSA_PKCS1_SHA512
    ]

-- | The schemes an RSA key signs under with PSS, under either kind of key.
rsaPssSchemes :: [SignatureScheme]
rsaPssSchemes =
    [ RSA_PSS_RSAE_SHA256
    , RSA_PSS_RSAE_SHA384
    , RSA_PSS_RSAE_SHA512
    , RSA_PSS_PSS_SHA256
    , RSA_PSS_PSS_SHA384
    , RSA_PSS_PSS_SHA512
    ]

-- | The schemes a DSA key signs under.
dsaSchemes :: [SignatureScheme]
dsaSchemes =
    [ DSA_MD5
    , DSA_SHA1
    , DSA_SHA224
    , DSA_SHA256
    , DSA_SHA384
    , DSA_SHA512
    ]

-- | The schemes an ECDSA key signs under.
ecdsaSchemes :: [SignatureScheme]
ecdsaSchemes =
    [ ECDSA_MD5
    , ECDSA_SHA1
    , ECDSA_SHA224
    , ECDSA_SECP256R1_SHA256
    , ECDSA_SECP384R1_SHA384
    , ECDSA_SECP521R1_SHA512
    ]

-- | What this library offers, best first.
supportedSignatureSchemes :: [SignatureScheme]
supportedSignatureSchemes =
    -- ML-DSA, TLS 1.3 only
    [ MLDSA87
    , MLDSA65
    , MLDSA44
    -- EdDSA
    , ED448
    , ED25519
    -- ECDSA
    , ECDSA_SECP521R1_SHA512
    , ECDSA_SECP384R1_SHA384
    , ECDSA_SECP256R1_SHA256
    -- RSASSA-PSS with an RSAE key
    , RSA_PSS_RSAE_SHA512
    , RSA_PSS_RSAE_SHA384
    , RSA_PSS_RSAE_SHA256
    -- RSASSA-PSS with a PSS key
    , RSA_PSS_PSS_SHA512
    , RSA_PSS_PSS_SHA384
    , RSA_PSS_PSS_SHA256
    -- RSASSA-PKCS1-v1_5
    , RSA_PKCS1_SHA512
    , RSA_PKCS1_SHA384
    , RSA_PKCS1_SHA256
    -- Legacy
    , RSA_PKCS1_SHA1
    , ECDSA_SHA1
    ]

-- | The subset of the above that TLS 1.3 allows.
signatureSchemesForTLS13 :: [SignatureScheme]
signatureSchemesForTLS13 =
    [ MLDSA87
    , MLDSA65
    , MLDSA44
    , ED448
    , ED25519
    , ECDSA_SECP521R1_SHA512
    , ECDSA_SECP384R1_SHA384
    , ECDSA_SECP256R1_SHA256
    , RSA_PSS_RSAE_SHA512
    , RSA_PSS_RSAE_SHA384
    , RSA_PSS_RSAE_SHA256
    , RSA_PSS_PSS_SHA512
    , RSA_PSS_PSS_SHA384
    , RSA_PSS_PSS_SHA256
    ]
{- FOURMOLU_ENABLE -}
