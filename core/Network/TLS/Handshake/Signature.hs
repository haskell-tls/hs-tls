{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Network.TLS.Handshake.Signature
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.Signature
    (
      createCertificateVerify
    , checkCertificateVerify
    , digitallySignDHParams
    , digitallySignECDHParams
    , digitallySignDHParamsVerify
    , digitallySignECDHParamsVerify
    , checkSupportedHashSignature
    , certificateCompatible
    , signatureCompatible
    , hashSigToCertType
    , signatureParams
    , fromPubKey
    , decryptError
    ) where

import Network.TLS.Crypto
import Network.TLS.Context.Internal
import Network.TLS.Parameters
import Network.TLS.Struct
import Network.TLS.Imports
import Network.TLS.Packet (generateCertificateVerify_SSL, generateCertificateVerify_SSL_DSS,
                           encodeSignedDHParams, encodeSignedECDHParams)
import Network.TLS.State
import Network.TLS.Handshake.State
import Network.TLS.Handshake.Key
import Network.TLS.Util

import Control.Monad.State.Strict

fromPubKey :: PubKey -> Maybe DigitalSignatureAlg
fromPubKey (PubKeyRSA _)     = Just DS_RSA
fromPubKey (PubKeyDSA _)     = Just DS_DSS
fromPubKey (PubKeyEC  _)     = Just DS_ECDSA
fromPubKey (PubKeyEd25519 _) = Just DS_Ed25519
fromPubKey (PubKeyEd448   _) = Just DS_Ed448
fromPubKey _                 = Nothing

decryptError :: MonadIO m => String -> m a
decryptError msg = throwCore $ Error_Protocol (msg, True, DecryptError)

-- | Check that the signature algorithm is compatible with a list of
-- 'CertificateType' values.  Ed25519 and Ed448 have no assigned code point
-- and are checked with extension "signature_algorithms" only.
certificateCompatible :: DigitalSignatureAlg -> [CertificateType] -> Bool
certificateCompatible DS_RSA     cTypes = CertificateType_RSA_Sign `elem` cTypes
certificateCompatible DS_DSS     cTypes = CertificateType_DSS_Sign `elem` cTypes
certificateCompatible DS_ECDSA   cTypes = CertificateType_ECDSA_Sign `elem` cTypes
certificateCompatible DS_Ed25519 _      = True
certificateCompatible DS_Ed448   _      = True

signatureCompatible :: DigitalSignatureAlg -> HashAndSignatureAlgorithm -> Bool
signatureCompatible DS_RSA     (_, SignatureRSA)              = True
signatureCompatible DS_RSA     (_, SignatureRSApssRSAeSHA256) = True
signatureCompatible DS_RSA     (_, SignatureRSApssRSAeSHA384) = True
signatureCompatible DS_RSA     (_, SignatureRSApssRSAeSHA512) = True
signatureCompatible DS_DSS     (_, SignatureDSS)              = True
signatureCompatible DS_ECDSA   (_, SignatureECDSA)            = True
signatureCompatible DS_Ed25519 (_, SignatureEd25519)          = True
signatureCompatible DS_Ed448   (_, SignatureEd448)            = True
signatureCompatible _          (_, _)                         = False

-- | Translate a 'HashAndSignatureAlgorithm' to an acceptable 'CertificateType'.
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
--
hashSigToCertType :: HashAndSignatureAlgorithm -> Maybe CertificateType
--
hashSigToCertType (_, SignatureRSA)   = Just CertificateType_RSA_Sign
--
hashSigToCertType (_, SignatureDSS)   = Just CertificateType_DSS_Sign
--
hashSigToCertType (_, SignatureECDSA) = Just CertificateType_ECDSA_Sign
--
hashSigToCertType (HashIntrinsic, SignatureRSApssRSAeSHA256)
    = Just CertificateType_RSA_Sign
hashSigToCertType (HashIntrinsic, SignatureRSApssRSAeSHA384)
    = Just CertificateType_RSA_Sign
hashSigToCertType (HashIntrinsic, SignatureRSApssRSAeSHA512)
    = Just CertificateType_RSA_Sign
hashSigToCertType (HashIntrinsic, SignatureEd25519)
    = Just CertificateType_Ed25519_Sign
hashSigToCertType (HashIntrinsic, SignatureEd448)
    = Just CertificateType_Ed448_Sign
--
hashSigToCertType _ = Nothing

checkCertificateVerify :: Context
                       -> Version
                       -> DigitalSignatureAlg
                       -> ByteString
                       -> DigitallySigned
                       -> IO Bool
checkCertificateVerify ctx usedVersion sigAlgExpected msgs digSig@(DigitallySigned hashSigAlg _) =
    case (usedVersion, hashSigAlg) of
        (TLS12, Nothing)    -> return False
        (TLS12, Just hs) | sigAlgExpected `signatureCompatible` hs -> doVerify
                         | otherwise                               -> return False
        (_,     Nothing)    -> doVerify
        (_,     Just _)     -> return False
  where
    doVerify =
        prepareCertificateVerifySignatureData ctx usedVersion sigAlgExpected hashSigAlg msgs >>=
        signatureVerifyWithCertVerifyData ctx digSig

createCertificateVerify :: Context
                        -> Version
                        -> DigitalSignatureAlg
                        -> Maybe HashAndSignatureAlgorithm -- TLS12 only
                        -> ByteString
                        -> IO DigitallySigned
createCertificateVerify ctx usedVersion sigAlg hashSigAlg msgs =
    prepareCertificateVerifySignatureData ctx usedVersion sigAlg hashSigAlg msgs >>=
    signatureCreateWithCertVerifyData ctx hashSigAlg

type CertVerifyData = (SignatureParams, ByteString)

-- in the case of TLS < 1.2, RSA signing, then the data need to be hashed first, as
-- the SHA1_MD5 algorithm expect an already digested data
buildVerifyData :: SignatureParams -> ByteString -> CertVerifyData
buildVerifyData (RSAParams SHA1_MD5 enc) bs = (RSAParams SHA1_MD5 enc, hashFinal $ hashUpdate (hashInit SHA1_MD5) bs)
buildVerifyData sigParam             bs = (sigParam, bs)

prepareCertificateVerifySignatureData :: Context
                                      -> Version
                                      -> DigitalSignatureAlg
                                      -> Maybe HashAndSignatureAlgorithm -- TLS12 only
                                      -> ByteString
                                      -> IO CertVerifyData
prepareCertificateVerifySignatureData ctx usedVersion sigAlg hashSigAlg msgs
    | usedVersion == SSL3 = do
        (hashCtx, params, generateCV_SSL) <-
            case sigAlg of
                DS_RSA -> return (hashInit SHA1_MD5, RSAParams SHA1_MD5 RSApkcs1, generateCertificateVerify_SSL)
                DS_DSS -> return (hashInit SHA1, DSSParams, generateCertificateVerify_SSL_DSS)
                _      -> throwCore $ Error_Misc ("unsupported CertificateVerify signature for SSL3: " ++ show sigAlg)
        Just masterSecret <- usingHState ctx $ gets hstMasterSecret
        return (params, generateCV_SSL masterSecret $ hashUpdate hashCtx msgs)
    | usedVersion == TLS10 || usedVersion == TLS11 =
            return $ buildVerifyData (signatureParams sigAlg Nothing) msgs
    | otherwise = return (signatureParams sigAlg hashSigAlg, msgs)

signatureParams :: DigitalSignatureAlg -> Maybe HashAndSignatureAlgorithm -> SignatureParams
signatureParams DS_RSA hashSigAlg =
    case hashSigAlg of
        Just (HashSHA512, SignatureRSA) -> RSAParams SHA512   RSApkcs1
        Just (HashSHA384, SignatureRSA) -> RSAParams SHA384   RSApkcs1
        Just (HashSHA256, SignatureRSA) -> RSAParams SHA256   RSApkcs1
        Just (HashSHA1  , SignatureRSA) -> RSAParams SHA1     RSApkcs1
        Just (HashIntrinsic , SignatureRSApssRSAeSHA512) -> RSAParams SHA512 RSApss
        Just (HashIntrinsic , SignatureRSApssRSAeSHA384) -> RSAParams SHA384 RSApss
        Just (HashIntrinsic , SignatureRSApssRSAeSHA256) -> RSAParams SHA256 RSApss
        Nothing                         -> RSAParams SHA1_MD5 RSApkcs1
        Just (hsh       , SignatureRSA) -> error ("unimplemented RSA signature hash type: " ++ show hsh)
        Just (_         , sigAlg)       -> error ("signature algorithm is incompatible with RSA: " ++ show sigAlg)
signatureParams DS_DSS hashSigAlg =
    case hashSigAlg of
        Nothing                       -> DSSParams
        Just (HashSHA1, SignatureDSS) -> DSSParams
        Just (_       , SignatureDSS) -> error "invalid DSA hash choice, only SHA1 allowed"
        Just (_       , sigAlg)       -> error ("signature algorithm is incompatible with DSS: " ++ show sigAlg)
signatureParams DS_ECDSA hashSigAlg =
    case hashSigAlg of
        Just (HashSHA512, SignatureECDSA) -> ECDSAParams SHA512
        Just (HashSHA384, SignatureECDSA) -> ECDSAParams SHA384
        Just (HashSHA256, SignatureECDSA) -> ECDSAParams SHA256
        Just (HashSHA1  , SignatureECDSA) -> ECDSAParams SHA1
        Nothing                           -> ECDSAParams SHA1
        Just (hsh       , SignatureECDSA) -> error ("unimplemented ECDSA signature hash type: " ++ show hsh)
        Just (_         , sigAlg)         -> error ("signature algorithm is incompatible with ECDSA: " ++ show sigAlg)
signatureParams DS_Ed25519 hashSigAlg =
    case hashSigAlg of
        Nothing                                 -> Ed25519Params
        Just (HashIntrinsic , SignatureEd25519) -> Ed25519Params
        Just (hsh           , SignatureEd25519) -> error ("unimplemented Ed25519 signature hash type: " ++ show hsh)
        Just (_             , sigAlg)           -> error ("signature algorithm is incompatible with Ed25519: " ++ show sigAlg)
signatureParams DS_Ed448 hashSigAlg =
    case hashSigAlg of
        Nothing                               -> Ed448Params
        Just (HashIntrinsic , SignatureEd448) -> Ed448Params
        Just (hsh           , SignatureEd448) -> error ("unimplemented Ed448 signature hash type: " ++ show hsh)
        Just (_             , sigAlg)         -> error ("signature algorithm is incompatible with Ed448: " ++ show sigAlg)

signatureCreateWithCertVerifyData :: Context
                                  -> Maybe HashAndSignatureAlgorithm
                                  -> CertVerifyData
                                  -> IO DigitallySigned
signatureCreateWithCertVerifyData ctx malg (sigParam, toSign) = do
    cc <- usingState_ ctx isClientContext
    DigitallySigned malg <$> signPrivate ctx cc sigParam toSign

signatureVerify :: Context -> DigitallySigned -> DigitalSignatureAlg -> ByteString -> IO Bool
signatureVerify ctx digSig@(DigitallySigned hashSigAlg _) sigAlgExpected toVerifyData = do
    usedVersion <- usingState_ ctx getVersion
    let (sigParam, toVerify) =
            case (usedVersion, hashSigAlg) of
                (TLS12, Nothing)    -> error "expecting hash and signature algorithm in a TLS12 digitally signed structure"
                (TLS12, Just hs) | sigAlgExpected `signatureCompatible` hs -> (signatureParams sigAlgExpected hashSigAlg, toVerifyData)
                                 | otherwise                               -> error "expecting different signature algorithm"
                (_,     Nothing)    -> buildVerifyData (signatureParams sigAlgExpected Nothing) toVerifyData
                (_,     Just _)     -> error "not expecting hash and signature algorithm in a < TLS12 digitially signed structure"
    signatureVerifyWithCertVerifyData ctx digSig (sigParam, toVerify)

signatureVerifyWithCertVerifyData :: Context
                                  -> DigitallySigned
                                  -> CertVerifyData
                                  -> IO Bool
signatureVerifyWithCertVerifyData ctx (DigitallySigned hs bs) (sigParam, toVerify) = do
    checkSupportedHashSignature ctx hs
    verifyPublic ctx sigParam toVerify bs

digitallySignParams :: Context -> ByteString -> DigitalSignatureAlg -> Maybe HashAndSignatureAlgorithm -> IO DigitallySigned
digitallySignParams ctx signatureData sigAlg hashSigAlg =
    let sigParam = signatureParams sigAlg hashSigAlg
     in signatureCreateWithCertVerifyData ctx hashSigAlg (buildVerifyData sigParam signatureData)

digitallySignDHParams :: Context
                      -> ServerDHParams
                      -> DigitalSignatureAlg
                      -> Maybe HashAndSignatureAlgorithm -- TLS12 only
                      -> IO DigitallySigned
digitallySignDHParams ctx serverParams sigAlg mhash = do
    dhParamsData <- withClientAndServerRandom ctx $ encodeSignedDHParams serverParams
    digitallySignParams ctx dhParamsData sigAlg mhash

digitallySignECDHParams :: Context
                        -> ServerECDHParams
                        -> DigitalSignatureAlg
                        -> Maybe HashAndSignatureAlgorithm -- TLS12 only
                        -> IO DigitallySigned
digitallySignECDHParams ctx serverParams sigAlg mhash = do
    ecdhParamsData <- withClientAndServerRandom ctx $ encodeSignedECDHParams serverParams
    digitallySignParams ctx ecdhParamsData sigAlg mhash

digitallySignDHParamsVerify :: Context
                            -> ServerDHParams
                            -> DigitalSignatureAlg
                            -> DigitallySigned
                            -> IO Bool
digitallySignDHParamsVerify ctx dhparams sigAlg signature = do
    expectedData <- withClientAndServerRandom ctx $ encodeSignedDHParams dhparams
    signatureVerify ctx signature sigAlg expectedData

digitallySignECDHParamsVerify :: Context
                              -> ServerECDHParams
                              -> DigitalSignatureAlg
                              -> DigitallySigned
                              -> IO Bool
digitallySignECDHParamsVerify ctx dhparams sigAlg signature = do
    expectedData <- withClientAndServerRandom ctx $ encodeSignedECDHParams dhparams
    signatureVerify ctx signature sigAlg expectedData

withClientAndServerRandom :: Context -> (ClientRandom -> ServerRandom -> b) -> IO b
withClientAndServerRandom ctx f = do
    (cran, sran) <- usingHState ctx $ (,) <$> gets hstClientRandom
                                          <*> (fromJust "withClientAndServer : server random" <$> gets hstServerRandom)
    return $ f cran sran

-- verify that the hash and signature selected by the peer is supported in
-- the local configuration
checkSupportedHashSignature :: Context -> Maybe HashAndSignatureAlgorithm -> IO ()
checkSupportedHashSignature _   Nothing   = return ()
checkSupportedHashSignature ctx (Just hs) =
    unless (hs `elem` supportedHashSignatures (ctxSupported ctx)) $
        let msg = "unsupported hash and signature algorithm: " ++ show hs
         in throwCore $ Error_Protocol (msg, True, IllegalParameter)
