{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.Signature (
    createCertificateVerify,
    checkCertificateVerify,
    digitallySignDHParams,
    digitallySignECDHParams,
    digitallySignDHParamsVerify,
    digitallySignECDHParamsVerify,
    checkSupportedHashSignature,
    certificateCompatible,
    signatureCompatible,
    signatureCompatible13,
    hashSigToCertType,
    signatureParams,
    decryptError,
) where

import Control.Monad.State.Strict

import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.State
import Network.TLS.Imports
import Network.TLS.Packet (
    encodeSignedDHParams,
    encodeSignedECDHParams,
 )
import Network.TLS.Parameters
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Types (invertRole)
import Network.TLS.X509

decryptError :: MonadIO m => String -> m a
decryptError msg = throwCore $ Error_Protocol msg DecryptError

-- | Check that the key is compatible with a list of 'CertificateType' values.
-- Ed25519 and Ed448 have no assigned code point and are checked with extension
-- "signature_algorithms" only.
certificateCompatible :: PubKey -> [CertificateType] -> Bool
certificateCompatible (PubKeyRSA _) cTypes = CertificateType_RSA_Sign `elem` cTypes
certificateCompatible (PubKeyDSA _) cTypes = CertificateType_DSA_Sign `elem` cTypes
certificateCompatible (PubKeyEC _) cTypes = CertificateType_ECDSA_Sign `elem` cTypes
certificateCompatible (PubKeyEd25519 _) _ = True
certificateCompatible (PubKeyEd448 _) _ = True
-- ML-DSA has no CertificateType of its own, as EdDSA does not either; what
-- a client may send is decided by signature_algorithms.
certificateCompatible (PubKeyMLDSA44 _) _ = True
certificateCompatible (PubKeyMLDSA65 _) _ = True
certificateCompatible (PubKeyMLDSA87 _) _ = True
certificateCompatible _ _ = False

signatureCompatible :: PubKey -> SignatureScheme -> Bool
-- ML-DSA first, and with a refusal for every other kind of key.  The RSA
-- equations below ignore the first byte, and ML-DSA's second byte is one
-- RSASSA-PSS also uses, so an ML-DSA scheme reaching them would be answered
-- for as though it were RSASSA-PSS.
signatureCompatible (PubKeyMLDSA44 _) MLDSA44 = True
signatureCompatible (PubKeyMLDSA65 _) MLDSA65 = True
signatureCompatible (PubKeyMLDSA87 _) MLDSA87 = True
signatureCompatible _ MLDSA44 = False
signatureCompatible _ MLDSA65 = False
signatureCompatible _ MLDSA87 = False
signatureCompatible (PubKeyRSA pk) RSA_PKCS1_SHA1 = kxCanUseRSApkcs1 pk SHA1
signatureCompatible (PubKeyRSA pk) RSA_PKCS1_SHA256 = kxCanUseRSApkcs1 pk SHA256
signatureCompatible (PubKeyRSA pk) RSA_PKCS1_SHA384 = kxCanUseRSApkcs1 pk SHA384
signatureCompatible (PubKeyRSA pk) RSA_PKCS1_SHA512 = kxCanUseRSApkcs1 pk SHA512
-- Only what signatureParams implements: a scheme it does not, such as
-- ecdsa_sha224, must not be chosen and then fail to sign.
signatureCompatible (PubKeyRSA pk) RSA_PSS_RSAE_SHA256 = kxCanUseRSApss pk SHA256
signatureCompatible (PubKeyRSA pk) RSA_PSS_RSAE_SHA384 = kxCanUseRSApss pk SHA384
signatureCompatible (PubKeyRSA pk) RSA_PSS_RSAE_SHA512 = kxCanUseRSApss pk SHA512
signatureCompatible (PubKeyDSA _) DSA_SHA1 = True
signatureCompatible (PubKeyEC _) sc =
    sc
        `elem` [ ECDSA_SHA1
               , ECDSA_SECP256R1_SHA256
               , ECDSA_SECP384R1_SHA384
               , ECDSA_SECP521R1_SHA512
               ]
signatureCompatible (PubKeyEd25519 _) ED25519 = True
signatureCompatible (PubKeyEd448 _) ED448 = True
signatureCompatible _ _ = False

-- Whether the signature algorithm is for the type of the key, whatever
-- its other parameters.
--
-- This takes the whole scheme and not its second byte alone, because
-- ML-DSA's second byte is one RSASSA-PSS also uses: only the pair says
-- which of the two a scheme is.  The ML-DSA equations come first for the
-- same reason -- an ML-DSA scheme fits no other kind of key, and one
-- ML-DSA size does not fit another's key.
keyTypeFits :: PubKey -> SignatureScheme -> Bool
keyTypeFits (PubKeyMLDSA44 _) hs = hs == MLDSA44
keyTypeFits (PubKeyMLDSA65 _) hs = hs == MLDSA65
keyTypeFits (PubKeyMLDSA87 _) hs = hs == MLDSA87
keyTypeFits _ MLDSA44 = False
keyTypeFits _ MLDSA65 = False
keyTypeFits _ MLDSA87 = False
keyTypeFits (PubKeyRSA _) sc = sc `elem` (rsaPkcs1Schemes ++ rsaPssSchemes)
keyTypeFits (PubKeyDSA _) sc = sc `elem` dsaSchemes
keyTypeFits (PubKeyEC _) sc = sc `elem` ecdsaSchemes
keyTypeFits (PubKeyEd25519 _) sc = sc == ED25519
keyTypeFits (PubKeyEd448 _) sc = sc == ED448
keyTypeFits _ _ = False

checkKeyTypeFits :: PubKey -> SignatureScheme -> IO ()
checkKeyTypeFits pubKey hs =
    unless (pubKey `keyTypeFits` hs) $
        throwCore $
            Error_Protocol
                ("signature algorithm " ++ show hs ++ " is for another type of key")
                IllegalParameter

-- Same as 'signatureCompatible' but for TLS13: for ECDSA this also checks the
-- relation between hash in the SignatureScheme and elliptic curve
signatureCompatible13 :: PubKey -> SignatureScheme -> Bool
signatureCompatible13 (PubKeyEC ecPub) sc
    | sc `elem` ecdsaSchemes =
        maybe False (\g -> findEllipticCurveGroup ecPub == Just g) (schemeCurve sc)
  where
    -- TLS 1.3 names the curve in the scheme; TLS 1.2 did not, and the three
    -- schemes that do not name one cannot be used there.
    schemeCurve ECDSA_SECP256R1_SHA256 = Just P256
    schemeCurve ECDSA_SECP384R1_SHA384 = Just P384
    schemeCurve ECDSA_SECP521R1_SHA512 = Just P521
    schemeCurve _ = Nothing
signatureCompatible13 pub hs = signatureCompatible pub hs

-- | Translate a 'SignatureScheme' to an acceptable 'CertificateType'.
-- Perhaps this needs to take supported groups into account, so that, for
-- example, if we don't support any shared ECDSA groups with the server, we
-- return 'Nothing' rather than 'CertificateType_ECDSA_Sign'.
--
-- Therefore, this interface is preliminary.  It gets us moving in the right
-- direction.  The interplay between all the various TLS extensions and
-- certificate selection is rather complex.
--
-- The goal is to ensure that the client certificate request callback only sees
-- 'CertificateType' values that are supported by the library and also
-- compatible with the server signature algorithms extension.
--
-- Since we don't yet support ECDSA private keys, the caller will use
-- 'lastSupportedCertificateType' to filter those out for now, leaving just
-- @RSA@ as the only supported client certificate algorithm for TLS 1.3.
--
-- FIXME: Add RSA_PSS_PSS signatures when supported.
hashSigToCertType :: SignatureScheme -> Maybe CertificateType
--
hashSigToCertType sc
    | sc `elem` rsaPkcs1Schemes = Just CertificateType_RSA_Sign
    | sc `elem` dsaSchemes = Just CertificateType_DSA_Sign
    | sc `elem` ecdsaSchemes = Just CertificateType_ECDSA_Sign
--
hashSigToCertType RSA_PSS_RSAE_SHA256 =
    Just CertificateType_RSA_Sign
hashSigToCertType RSA_PSS_RSAE_SHA384 =
    Just CertificateType_RSA_Sign
hashSigToCertType RSA_PSS_RSAE_SHA512 =
    Just CertificateType_RSA_Sign
hashSigToCertType ED25519 =
    Just CertificateType_Ed25519_Sign
hashSigToCertType ED448 =
    Just CertificateType_Ed448_Sign
--
hashSigToCertType _ = Nothing

checkCertificateVerify
    :: Context
    -> Version
    -> PubKey
    -> ByteString
    -> DigitallySigned
    -> IO Bool
-- An algorithm not offered in CertificateRequest (RFC 5246 Section
-- 7.4.8), or one for another type of key, is a field that is incorrect,
-- an illegal_parameter.  One for the right type of key that still does
-- not fit it, an RSASSA-PSS one for an rsaEncryption key say, is a
-- signature that does not verify, a decrypt_error, which False leads to.
checkCertificateVerify ctx usedVersion pubKey msgs digSig@(DigitallySigned hashSigAlg _) = do
    -- ML-DSA is defined for TLS 1.3 only, so naming one here is a field
    -- that is incorrect whatever key the peer holds.
    when (usedVersion < TLS13 && isMLDSA hashSigAlg) $
        throwCore $
            Error_Protocol
                ("signature algorithm " ++ show hashSigAlg ++ " is not for " ++ show usedVersion)
                IllegalParameter
    checkSupportedHashSignature ctx hashSigAlg
    checkKeyTypeFits pubKey hashSigAlg
    if pubKey `signatureCompatible` hashSigAlg
        then doVerify
        else return False
  where
    doVerify =
        prepareCertificateVerifySignatureData ctx usedVersion pubKey hashSigAlg msgs
            >>= signatureVerifyWithCertVerifyData ctx digSig

createCertificateVerify
    :: Context
    -> Version
    -> PubKey
    -> SignatureScheme -- TLS12 only
    -> ByteString
    -> IO DigitallySigned
createCertificateVerify ctx usedVersion pubKey hashSigAlg msgs =
    prepareCertificateVerifySignatureData ctx usedVersion pubKey hashSigAlg msgs
        >>= signatureCreateWithCertVerifyData ctx hashSigAlg

type CertVerifyData = (SignatureParams, ByteString)

-- in the case of TLS < 1.2, RSA signing, then the data need to be hashed first, as
-- the SHA1_MD5 algorithm expect an already digested data
buildVerifyData :: SignatureParams -> ByteString -> CertVerifyData
buildVerifyData (RSAParams SHA1_MD5 enc) bs = (RSAParams SHA1_MD5 enc, hashFinal $ hashUpdate (hashInit SHA1_MD5) bs)
buildVerifyData sigParam bs = (sigParam, bs)

prepareCertificateVerifySignatureData
    :: Context
    -> Version
    -> PubKey
    -> SignatureScheme -- TLS12 only
    -> ByteString
    -> IO CertVerifyData
prepareCertificateVerifySignatureData _ctx _usedVersion pubKey hashSigAlg msgs =
    return (signatureParams pubKey hashSigAlg, msgs)

signatureParams :: PubKey -> SignatureScheme -> SignatureParams
-- Which of these is used is decided by the key, and signatureCompatible has
-- already refused a scheme that does not fit the key, so an ML-DSA scheme
-- cannot arrive at a clause for another kind of key.
signatureParams (PubKeyRSA _) hashSigAlg =
    case hashSigAlg of
        RSA_PKCS1_SHA512 -> RSAParams SHA512 RSApkcs1
        RSA_PKCS1_SHA384 -> RSAParams SHA384 RSApkcs1
        RSA_PKCS1_SHA256 -> RSAParams SHA256 RSApkcs1
        RSA_PKCS1_SHA1 -> RSAParams SHA1 RSApkcs1
        RSA_PSS_RSAE_SHA512 -> RSAParams SHA512 RSApss
        RSA_PSS_RSAE_SHA384 -> RSAParams SHA384 RSApss
        RSA_PSS_RSAE_SHA256 -> RSAParams SHA256 RSApss
        sc
            | sc `elem` rsaPkcs1Schemes || sc `elem` rsaPssSchemes ->
                error ("unimplemented RSA signature scheme: " ++ show sc)
            | otherwise ->
                error ("signature scheme is incompatible with RSA: " ++ show sc)
signatureParams (PubKeyDSA _) hashSigAlg =
    case hashSigAlg of
        DSA_SHA1 -> DSAParams
        sc
            | sc `elem` dsaSchemes -> error "invalid DSA hash choice, only SHA1 allowed"
            | otherwise ->
                error ("signature scheme is incompatible with DSA: " ++ show sc)
signatureParams (PubKeyEC _) hashSigAlg =
    case hashSigAlg of
        ECDSA_SECP521R1_SHA512 -> ECDSAParams SHA512
        ECDSA_SECP384R1_SHA384 -> ECDSAParams SHA384
        ECDSA_SECP256R1_SHA256 -> ECDSAParams SHA256
        ECDSA_SHA1 -> ECDSAParams SHA1
        sc
            | sc `elem` ecdsaSchemes ->
                error ("unimplemented ECDSA signature scheme: " ++ show sc)
            | otherwise ->
                error ("signature scheme is incompatible with ECDSA: " ++ show sc)
signatureParams (PubKeyEd25519 _) hashSigAlg =
    case hashSigAlg of
        ED25519 -> Ed25519Params
        sc -> error ("signature scheme is incompatible with Ed25519: " ++ show sc)
signatureParams (PubKeyEd448 _) hashSigAlg =
    case hashSigAlg of
        ED448 -> Ed448Params
        sc -> error ("signature scheme is incompatible with Ed448: " ++ show sc)
signatureParams (PubKeyMLDSA44 _) MLDSA44 = MLDSA44Params
signatureParams (PubKeyMLDSA65 _) MLDSA65 = MLDSA65Params
signatureParams (PubKeyMLDSA87 _) MLDSA87 = MLDSA87Params
signatureParams pk _ = error ("signatureParams: " ++ pubkeyType pk ++ " is not supported")

signatureCreateWithCertVerifyData
    :: Context
    -> SignatureScheme
    -> CertVerifyData
    -> IO DigitallySigned
signatureCreateWithCertVerifyData ctx malg (sigParam, toSign) = do
    role <- usingState_ ctx getRole
    usingHState ctx $ setSignatureScheme role malg
    DigitallySigned malg <$> signPrivate ctx role sigParam toSign

signatureVerify :: Context -> DigitallySigned -> PubKey -> ByteString -> IO Bool
-- Checked as checkCertificateVerify does: the peer chose the algorithm, so
-- one that does not fit the key is its error, not ours.
signatureVerify ctx digSig@(DigitallySigned hashSigAlg _) pubKey toVerifyData = do
    usedVersion <- usingState_ ctx getVersion
    unless (usedVersion == TLS12) $
        throwCore $
            Error_Protocol
                ("no signature algorithm in a " ++ show usedVersion ++ " digitally-signed")
                InternalError
    checkSupportedHashSignature ctx hashSigAlg
    checkKeyTypeFits pubKey hashSigAlg
    if pubKey `signatureCompatible` hashSigAlg
        then
            signatureVerifyWithCertVerifyData
                ctx
                digSig
                (signatureParams pubKey hashSigAlg, toVerifyData)
        else return False

signatureVerifyWithCertVerifyData
    :: Context
    -> DigitallySigned
    -> CertVerifyData
    -> IO Bool
signatureVerifyWithCertVerifyData ctx (DigitallySigned hs bs) (sigParam, toVerify) = do
    checkSupportedHashSignature ctx hs
    ok <- verifyPublic ctx sigParam toVerify bs
    when ok $ do
        role <- usingState_ ctx getRole
        usingHState ctx $ setSignatureScheme (invertRole role) hs
    return ok

digitallySignParams
    :: Context
    -> ByteString
    -> PubKey
    -> SignatureScheme
    -> IO DigitallySigned
digitallySignParams ctx signatureData pubKey hashSigAlg =
    let sigParam = signatureParams pubKey hashSigAlg
     in signatureCreateWithCertVerifyData
            ctx
            hashSigAlg
            (buildVerifyData sigParam signatureData)

digitallySignDHParams
    :: Context
    -> ServerDHParams
    -> PubKey
    -> SignatureScheme -- TLS12 only
    -> IO DigitallySigned
digitallySignDHParams ctx serverParams pubKey mhash = do
    dhParamsData <-
        withClientAndServerRandom ctx $ encodeSignedDHParams serverParams
    digitallySignParams ctx dhParamsData pubKey mhash

digitallySignECDHParams
    :: Context
    -> ServerECDHParams
    -> PubKey
    -> SignatureScheme -- TLS12 only
    -> IO DigitallySigned
digitallySignECDHParams ctx serverParams pubKey mhash = do
    ecdhParamsData <-
        withClientAndServerRandom ctx $ encodeSignedECDHParams serverParams
    digitallySignParams ctx ecdhParamsData pubKey mhash

digitallySignDHParamsVerify
    :: Context
    -> ServerDHParams
    -> PubKey
    -> DigitallySigned
    -> IO Bool
digitallySignDHParamsVerify ctx dhparams pubKey signature = do
    expectedData <- withClientAndServerRandom ctx $ encodeSignedDHParams dhparams
    signatureVerify ctx signature pubKey expectedData

digitallySignECDHParamsVerify
    :: Context
    -> ServerECDHParams
    -> PubKey
    -> DigitallySigned
    -> IO Bool
digitallySignECDHParamsVerify ctx dhparams pubKey signature = do
    expectedData <- withClientAndServerRandom ctx $ encodeSignedECDHParams dhparams
    signatureVerify ctx signature pubKey expectedData

withClientAndServerRandom
    :: Context -> (ClientRandom -> ServerRandom -> b) -> IO b
withClientAndServerRandom ctx f = do
    (cran, sran) <-
        usingHState ctx $
            (,)
                <$> gets hstClientRandom
                <*> (fromJust <$> gets hstServerRandom)
    return $ f cran sran

-- verify that the hash and signature selected by the peer is supported in
-- the local configuration
checkSupportedHashSignature
    :: Context -> SignatureScheme -> IO ()
checkSupportedHashSignature ctx hs =
    unless (hs `elem` supportedHashSignatures (ctxSupported ctx)) $
        let msg = "unsupported hash and signature algorithm: " ++ show hs
         in throwCore $ Error_Protocol msg IllegalParameter
