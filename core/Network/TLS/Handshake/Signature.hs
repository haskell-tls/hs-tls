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

certificateVerifyCheck :: Context
                       -> Version
                       -> SignatureAlgorithm
                       -> Bytes
                       -> DigitallySigned
                       -> IO Bool
certificateVerifyCheck ctx usedVersion sigAlgExpected msgs digSig@(DigitallySigned hashSigAlg _) =
    case (usedVersion, hashSigAlg) of
        (TLS12, Nothing)    -> return False
        (TLS12, Just (h,s)) | s == sigAlgExpected -> doVerify (Just h)
                            | otherwise           -> return False
        (_,     Nothing)    -> doVerify Nothing
        (_,     Just _)     -> return False
  where
    doVerify mhash =
        prepareCertificateVerifySignatureData ctx usedVersion sigAlgExpected mhash msgs >>=
        signatureVerifyWithHashDescr ctx sigAlgExpected digSig

certificateVerifyCreate :: Context
                        -> Version
                        -> SignatureAlgorithm
                        -> Maybe HashAlgorithm -- TLS12 only
                        -> Bytes
                        -> IO DigitallySigned
certificateVerifyCreate ctx usedVersion sigAlg mhash msgs =
    prepareCertificateVerifySignatureData ctx usedVersion sigAlg mhash msgs >>=
    signatureCreateWithHashDescr ctx (toAlg `fmap` mhash)
  where
    toAlg hashAlg = (hashAlg, sigAlg)

type CertVerifyData = (Hash, Bytes)

prepareCertificateVerifySignatureData :: Context
                                      -> Version
                                      -> SignatureAlgorithm
                                      -> Maybe HashAlgorithm -- TLS12 only
                                      -> Bytes
                                      -> IO CertVerifyData
prepareCertificateVerifySignatureData ctx usedVersion sigAlg mhash msgs
    | usedVersion == SSL3 = do
        (h, generateCV_SSL) <-
            case sigAlg of
                SignatureRSA -> return (SHA1_MD5, generateCertificateVerify_SSL)
                SignatureDSS -> return (SHA1, generateCertificateVerify_SSL_DSS)
                _            -> throwCore $ Error_Misc ("unsupported CertificateVerify signature for SSL3: " ++ show sigAlg)
        Just masterSecret <- usingHState ctx $ gets hstMasterSecret
        return (h, generateCV_SSL masterSecret (hashUpdate (hashInit h) msgs))
    | usedVersion == TLS10 || usedVersion == TLS11 =
        case signatureHashData sigAlg Nothing of
            SHA1_MD5 -> return (SHA1_MD5, hashFinal $ hashUpdate (hashInit SHA1_MD5) msgs)
            alg      -> return (alg, msgs)
    | otherwise = return (signatureHashData sigAlg mhash, msgs)

signatureHashData :: SignatureAlgorithm -> Maybe HashAlgorithm -> Hash
signatureHashData SignatureRSA mhash =
    case mhash of
        Just HashSHA512 -> SHA512
        Just HashSHA384 -> SHA384
        Just HashSHA256 -> SHA256
        Just HashSHA1   -> SHA1
        Nothing         -> SHA1_MD5
        Just hsh        -> error ("unimplemented RSA signature hash type: " ++ show hsh)
signatureHashData SignatureDSS mhash =
    case mhash of
        Nothing       -> SHA1
        Just HashSHA1 -> SHA1
        Just _        -> error "invalid DSA hash choice, only SHA1 allowed"
signatureHashData SignatureECDSA mhash =
    case mhash of
        Just HashSHA512 -> SHA512
        Just HashSHA384 -> SHA384
        Just HashSHA256 -> SHA256
        Just HashSHA1   -> SHA1
        Nothing         -> SHA1
        Just hsh        -> error ("unimplemented ECDSA signature hash type: " ++ show hsh)
signatureHashData sig _ = error ("unimplemented signature type: " ++ show sig)

--signatureCreate :: Context -> Maybe HashAndSignatureAlgorithm -> HashDescr -> Bytes -> IO DigitallySigned
signatureCreate :: Context -> Maybe HashAndSignatureAlgorithm -> CertVerifyData -> IO DigitallySigned
signatureCreate ctx malg (hashAlg, toSign) =
    -- in the case of TLS < 1.2, RSA signing, then the data need to be hashed first, as
    -- the SHA_MD5 algorithm expect an already digested data
    let signData =
            case (malg, hashAlg) of
                (Nothing, SHA1_MD5) -> hashFinal $ hashUpdate (hashInit SHA1_MD5) toSign
                _                   -> toSign
    in signatureCreateWithHashDescr ctx malg (hashAlg, signData)

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
    -- in the case of TLS < 1.2, RSA signing, then the data need to be hashed first, as
    -- the SHA_MD5 algorithm expect an already digested data
    let (hashDescr, toVerify) =
            case (usedVersion, hashSigAlg) of
                (TLS12, Nothing)    -> error "expecting hash and signature algorithm in a TLS12 digitally signed structure"
                (TLS12, Just (h,s)) | s == sigAlgExpected -> (signatureHashData sigAlgExpected (Just h), toVerifyData)
                                    | otherwise           -> error "expecting different signature algorithm"
                (_,     Nothing)    -> case signatureHashData sigAlgExpected Nothing of
                                            SHA1_MD5 -> (SHA1_MD5, hashFinal $ hashUpdate (hashInit SHA1_MD5) toVerifyData)
                                            alg      -> (alg, toVerifyData)
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

digitallySignParams :: Context -> Bytes -> SignatureAlgorithm -> Maybe HashAlgorithm -> IO DigitallySigned
digitallySignParams ctx signatureData sigAlg mhash = do
    let hashDescr = signatureHashData sigAlg mhash
    signatureCreate ctx (fmap (\h -> (h, sigAlg)) mhash) (hashDescr, signatureData)

digitallySignDHParams :: Context
                      -> ServerDHParams
                      -> SignatureAlgorithm
                      -> Maybe HashAlgorithm -- TLS12 only
                      -> IO DigitallySigned
digitallySignDHParams ctx serverParams sigAlg mhash = do
    dhParamsData <- withClientAndServerRandom ctx $ encodeSignedDHParams serverParams
    digitallySignParams ctx dhParamsData sigAlg mhash

digitallySignECDHParams :: Context
                        -> ServerECDHParams
                        -> SignatureAlgorithm
                        -> Maybe HashAlgorithm -- TLS12 only
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
