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

import Data.ByteString (ByteString)
import Control.Monad.State.Strict

signatureCompatible :: DigitalSignatureAlg -> HashAndSignatureAlgorithm -> Bool
signatureCompatible RSA   (_, SignatureRSA)          = True
signatureCompatible RSA   (_, SignatureRSApssSHA256) = True
signatureCompatible RSA   (_, SignatureRSApssSHA384) = True
signatureCompatible RSA   (_, SignatureRSApssSHA512) = True
signatureCompatible DSS   (_, SignatureDSS)          = True
signatureCompatible ECDSA (_, SignatureECDSA)        = True
signatureCompatible _     (_, _)                     = False

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
                RSA -> return (hashInit SHA1_MD5, RSAParams SHA1_MD5 RSApkcs1, generateCertificateVerify_SSL)
                DSS -> return (hashInit SHA1, DSSParams, generateCertificateVerify_SSL_DSS)
                _   -> throwCore $ Error_Misc ("unsupported CertificateVerify signature for SSL3: " ++ show sigAlg)
        Just masterSecret <- usingHState ctx $ gets hstMasterSecret
        return (params, generateCV_SSL masterSecret $ hashUpdate hashCtx msgs)
    | usedVersion == TLS10 || usedVersion == TLS11 =
            return $ buildVerifyData (signatureParams sigAlg Nothing) msgs
    | otherwise = return (signatureParams sigAlg hashSigAlg, msgs)

signatureParams :: DigitalSignatureAlg -> Maybe HashAndSignatureAlgorithm -> SignatureParams
signatureParams RSA hashSigAlg =
    case hashSigAlg of
        Just (HashSHA512, SignatureRSA) -> RSAParams SHA512   RSApkcs1
        Just (HashSHA384, SignatureRSA) -> RSAParams SHA384   RSApkcs1
        Just (HashSHA256, SignatureRSA) -> RSAParams SHA256   RSApkcs1
        Just (HashSHA1  , SignatureRSA) -> RSAParams SHA1     RSApkcs1
        Just (HashIntrinsic , SignatureRSApssSHA512) -> RSAParams SHA512 RSApss
        Just (HashIntrinsic , SignatureRSApssSHA384) -> RSAParams SHA384 RSApss
        Just (HashIntrinsic , SignatureRSApssSHA256) -> RSAParams SHA256 RSApss
        Nothing                         -> RSAParams SHA1_MD5 RSApkcs1
        Just (hsh       , SignatureRSA) -> error ("unimplemented RSA signature hash type: " ++ show hsh)
        Just (_         , sigAlg)       -> error ("signature algorithm is incompatible with RSA: " ++ show sigAlg)
signatureParams DSS hashSigAlg =
    case hashSigAlg of
        Nothing                       -> DSSParams
        Just (HashSHA1, SignatureDSS) -> DSSParams
        Just (_       , SignatureDSS) -> error "invalid DSA hash choice, only SHA1 allowed"
        Just (_       , sigAlg)       -> error ("signature algorithm is incompatible with DSS: " ++ show sigAlg)
signatureParams ECDSA hashSigAlg =
    case hashSigAlg of
        Just (HashSHA512, SignatureECDSA) -> ECDSAParams SHA512
        Just (HashSHA384, SignatureECDSA) -> ECDSAParams SHA384
        Just (HashSHA256, SignatureECDSA) -> ECDSAParams SHA256
        Just (HashSHA1  , SignatureECDSA) -> ECDSAParams SHA1
        Nothing                           -> ECDSAParams SHA1
        Just (hsh       , SignatureECDSA) -> error ("unimplemented ECDSA signature hash type: " ++ show hsh)
        Just (_         , sigAlg)         -> error ("signature algorithm is incompatible with ECDSA: " ++ show sigAlg)
signatureParams sig _ = error ("unimplemented signature type: " ++ show sig)

signatureCreateWithCertVerifyData :: Context
                                  -> Maybe HashAndSignatureAlgorithm
                                  -> CertVerifyData
                                  -> IO DigitallySigned
signatureCreateWithCertVerifyData ctx malg (sigParam, toSign) = do
    cc <- usingState_ ctx $ isClientContext
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
signatureVerifyWithCertVerifyData ctx (DigitallySigned _ bs) (sigParam, toVerify) = do
    cc <- usingState_ ctx $ isClientContext
    verifyPublic ctx cc sigParam toVerify bs

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
