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
      certificateVerifyCreate
    , certificateVerifyCheck
    , digitallySignDHParams
    , digitallySignECDHParams
    , digitallySignDHParamsVerify
    , digitallySignECDHParamsVerify
    , signatureCompatible
    ) where

import Network.TLS.Crypto
import Network.TLS.Context.Internal
import Network.TLS.Struct
import Network.TLS.Imports
import Network.TLS.Packet (generateCertificateVerify_SSL, generateCertificateVerify_SSL_DSS,
                           encodeSignedDHParams, encodeSignedECDHParams)
import Network.TLS.State
import Network.TLS.Handshake.State
import Network.TLS.Handshake.Key
import Network.TLS.Util

import Control.Monad.State

signatureCompatible :: SignatureAlgorithm -> HashAndSignatureAlgorithm -> Bool
signatureCompatible sigAlgExpected (_, s) = s == sigAlgExpected

certificateVerifyCheck :: Context
                       -> Version
                       -> SignatureAlgorithm
                       -> Bytes
                       -> DigitallySigned
                       -> IO Bool
certificateVerifyCheck ctx usedVersion sigAlgExpected msgs digSig@(DigitallySigned hashSigAlg _) =
    case (usedVersion, hashSigAlg) of
        (TLS12, Nothing)    -> return False
        (TLS12, Just hs) | sigAlgExpected `signatureCompatible` hs -> doVerify
                         | otherwise                               -> return False
        (_,     Nothing)    -> doVerify
        (_,     Just _)     -> return False
  where
    doVerify =
        prepareCertificateVerifySignatureData ctx usedVersion sigAlgExpected hashSigAlg msgs >>=
        signatureVerifyWithHashDescr ctx sigAlgExpected digSig

certificateVerifyCreate :: Context
                        -> Version
                        -> SignatureAlgorithm
                        -> Maybe HashAndSignatureAlgorithm -- TLS12 only
                        -> Bytes
                        -> IO DigitallySigned
certificateVerifyCreate ctx usedVersion sigAlg hashSigAlg msgs =
    prepareCertificateVerifySignatureData ctx usedVersion sigAlg hashSigAlg msgs >>=
    signatureCreateWithHashDescr ctx hashSigAlg

type CertVerifyData = (SignatureParams, Bytes)

-- in the case of TLS < 1.2, RSA signing, then the data need to be hashed first, as
-- the SHA1_MD5 algorithm expect an already digested data
buildVerifyData :: SignatureParams -> Bytes -> CertVerifyData
buildVerifyData (RSAParams SHA1_MD5) bs = (RSAParams SHA1_MD5, hashFinal $ hashUpdate (hashInit SHA1_MD5) bs)
buildVerifyData hashDescr            bs = (hashDescr, bs)

prepareCertificateVerifySignatureData :: Context
                                      -> Version
                                      -> SignatureAlgorithm
                                      -> Maybe HashAndSignatureAlgorithm -- TLS12 only
                                      -> Bytes
                                      -> IO CertVerifyData
prepareCertificateVerifySignatureData ctx usedVersion sigAlg hashSigAlg msgs
    | usedVersion == SSL3 = do
        (hashCtx, params, generateCV_SSL) <-
            case sigAlg of
                SignatureRSA -> return (hashInit SHA1_MD5, RSAParams SHA1_MD5, generateCertificateVerify_SSL)
                SignatureDSS -> return (hashInit SHA1, DSSParams, generateCertificateVerify_SSL_DSS)
                _            -> throwCore $ Error_Misc ("unsupported CertificateVerify signature for SSL3: " ++ show sigAlg)
        Just masterSecret <- usingHState ctx $ gets hstMasterSecret
        return (params, generateCV_SSL masterSecret $ hashUpdate hashCtx msgs)
    | usedVersion == TLS10 || usedVersion == TLS11 =
            return $ buildVerifyData (signatureParams sigAlg Nothing) msgs
    | otherwise = return (signatureParams sigAlg hashSigAlg, msgs)

signatureParams :: SignatureAlgorithm -> Maybe HashAndSignatureAlgorithm -> SignatureParams
signatureParams SignatureRSA hashSigAlg =
    case hashSigAlg of
        Just (HashSHA512, SignatureRSA) -> RSAParams SHA512
        Just (HashSHA384, SignatureRSA) -> RSAParams SHA384
        Just (HashSHA256, SignatureRSA) -> RSAParams SHA256
        Just (HashSHA1  , SignatureRSA) -> RSAParams SHA1
        Nothing                         -> RSAParams SHA1_MD5
        Just (hsh       , SignatureRSA) -> error ("unimplemented RSA signature hash type: " ++ show hsh)
        Just (_         , sigAlg)       -> error ("signature type is incompatible with RSA: " ++ show sigAlg)
signatureParams SignatureDSS hashSigAlg =
    case hashSigAlg of
        Nothing                       -> DSSParams
        Just (HashSHA1, SignatureDSS) -> DSSParams
        Just (_       , SignatureDSS) -> error "invalid DSA hash choice, only SHA1 allowed"
        Just (_       , sigAlg)       -> error ("signature type is incompatible with DSS: " ++ show sigAlg)
signatureParams SignatureECDSA hashSigAlg =
    case hashSigAlg of
        Just (HashSHA512, SignatureECDSA) -> ECDSAParams SHA512
        Just (HashSHA384, SignatureECDSA) -> ECDSAParams SHA384
        Just (HashSHA256, SignatureECDSA) -> ECDSAParams SHA256
        Just (HashSHA1  , SignatureECDSA) -> ECDSAParams SHA1
        Nothing                           -> ECDSAParams SHA1
        Just (hsh       , SignatureECDSA) -> error ("unimplemented ECDSA signature hash type: " ++ show hsh)
        Just (_         , sigAlg)         -> error ("signature type is incompatible with ECDSA: " ++ show sigAlg)
signatureParams sig _ = error ("unimplemented signature type: " ++ show sig)

signatureCreateWithHashDescr :: Context
                             -> Maybe HashAndSignatureAlgorithm
                             -> CertVerifyData
                             -> IO DigitallySigned
signatureCreateWithHashDescr ctx malg (hashDescr, toSign) = do
    cc <- usingState_ ctx $ isClientContext
    DigitallySigned malg <$> signPrivate ctx cc hashDescr toSign

signatureVerify :: Context -> DigitallySigned -> SignatureAlgorithm -> Bytes -> IO Bool
signatureVerify ctx digSig@(DigitallySigned hashSigAlg _) sigAlgExpected toVerifyData = do
    usedVersion <- usingState_ ctx getVersion
    let (hashDescr, toVerify) =
            case (usedVersion, hashSigAlg) of
                (TLS12, Nothing)    -> error "expecting hash and signature algorithm in a TLS12 digitally signed structure"
                (TLS12, Just hs) | sigAlgExpected `signatureCompatible` hs -> (signatureParams sigAlgExpected hashSigAlg, toVerifyData)
                                 | otherwise                               -> error "expecting different signature algorithm"
                (_,     Nothing)    -> buildVerifyData (signatureParams sigAlgExpected Nothing) toVerifyData
                (_,     Just _)     -> error "not expecting hash and signature algorithm in a < TLS12 digitially signed structure"
    signatureVerifyWithHashDescr ctx sigAlgExpected digSig (hashDescr, toVerify)

signatureVerifyWithHashDescr :: Context
                             -> SignatureAlgorithm
                             -> DigitallySigned
                             -> CertVerifyData
                             -> IO Bool
signatureVerifyWithHashDescr ctx sigAlgExpected (DigitallySigned _ bs) (hashDescr, toVerify) = do
    cc <- usingState_ ctx $ isClientContext
    case sigAlgExpected of
        SignatureRSA   -> verifyPublic ctx cc hashDescr toVerify bs
        SignatureDSS   -> verifyPublic ctx cc hashDescr toVerify bs
        SignatureECDSA -> verifyPublic ctx cc hashDescr toVerify bs
        _              -> error "signature verification not implemented yet"

digitallySignParams :: Context -> Bytes -> SignatureAlgorithm -> Maybe HashAndSignatureAlgorithm -> IO DigitallySigned
digitallySignParams ctx signatureData sigAlg hashSigAlg =
    let hashDescr = signatureParams sigAlg hashSigAlg
     in signatureCreateWithHashDescr ctx hashSigAlg (buildVerifyData hashDescr signatureData)

digitallySignDHParams :: Context
                      -> ServerDHParams
                      -> SignatureAlgorithm
                      -> Maybe HashAndSignatureAlgorithm -- TLS12 only
                      -> IO DigitallySigned
digitallySignDHParams ctx serverParams sigAlg mhash = do
    dhParamsData <- withClientAndServerRandom ctx $ encodeSignedDHParams serverParams
    digitallySignParams ctx dhParamsData sigAlg mhash

digitallySignECDHParams :: Context
                        -> ServerECDHParams
                        -> SignatureAlgorithm
                        -> Maybe HashAndSignatureAlgorithm -- TLS12 only
                        -> IO DigitallySigned
digitallySignECDHParams ctx serverParams sigAlg mhash = do
    ecdhParamsData <- withClientAndServerRandom ctx $ encodeSignedECDHParams serverParams
    digitallySignParams ctx ecdhParamsData sigAlg mhash

digitallySignDHParamsVerify :: Context
                            -> ServerDHParams
                            -> SignatureAlgorithm
                            -> DigitallySigned
                            -> IO Bool
digitallySignDHParamsVerify ctx dhparams sigAlg signature = do
    expectedData <- withClientAndServerRandom ctx $ encodeSignedDHParams dhparams
    signatureVerify ctx signature sigAlg expectedData

digitallySignECDHParamsVerify :: Context
                              -> ServerECDHParams
                              -> SignatureAlgorithm
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
