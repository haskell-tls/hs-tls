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
import Network.TLS.Packet (generateCertificateVerify_SSL, encodeSignedDHParams, encodeSignedECDHParams)
import Network.TLS.Parameters (supportedHashSignatures)
import Network.TLS.State
import Network.TLS.Handshake.State
import Network.TLS.Handshake.Key
import Network.TLS.Util

import Control.Applicative
import Control.Monad.State

certificateVerifyCheck :: Context
                       -> Version
                       -> Maybe HashAndSignatureAlgorithm
                       -> Bytes
                       -> DigitallySigned
                       -> IO Bool
certificateVerifyCheck ctx usedVersion malg msgs dsig =
    prepareCertificateVerifySignatureData ctx usedVersion malg msgs >>=
    signatureVerifyWithHashDescr ctx SignatureRSA dsig

certificateVerifyCreate :: Context
                        -> Version
                        -> Maybe HashAndSignatureAlgorithm
                        -> Bytes
                        -> IO DigitallySigned
certificateVerifyCreate ctx usedVersion malg msgs =
    prepareCertificateVerifySignatureData ctx usedVersion malg msgs >>=
    signatureCreate ctx malg

getHashAndASN1 :: MonadIO m => (HashAlgorithm, SignatureAlgorithm) -> m Hash
getHashAndASN1 hashSig = case hashSig of
    (HashSHA1,   SignatureRSA) -> return SHA1
    (HashSHA224, SignatureRSA) -> return SHA224
    (HashSHA256, SignatureRSA) -> return SHA256
    (HashSHA384, SignatureRSA) -> return SHA384
    (HashSHA512, SignatureRSA) -> return SHA512
    _                          -> throwCore $ Error_Misc "unsupported hash/sig algorithm"

type CertVerifyData = (Hash, Bytes)

prepareCertificateVerifySignatureData :: Context
                                      -> Version
                                      -> Maybe HashAndSignatureAlgorithm
                                      -> Bytes
                                      -> IO CertVerifyData
prepareCertificateVerifySignatureData ctx usedVersion malg msgs
    | usedVersion == SSL3 = do
        Just masterSecret <- usingHState ctx $ gets hstMasterSecret
        return (SHA1_MD5, generateCertificateVerify_SSL masterSecret (hashUpdate (hashInit SHA1_MD5) msgs))
    | usedVersion == TLS10 || usedVersion == TLS11 = do
        return (SHA1_MD5, hashFinal $ hashUpdate (hashInit SHA1_MD5) msgs)
    | otherwise = do
        let Just hashSig = malg
        hsh <- getHashAndASN1 hashSig
        return (hsh, msgs)

signatureHashData :: SignatureAlgorithm -> Maybe HashAlgorithm -> Hash
signatureHashData SignatureRSA mhash =
    case mhash of
        Just HashSHA512 -> SHA512
        Just HashSHA384 -> SHA384
        Just HashSHA256 -> SHA256
        Just HashSHA1   -> SHA1
        Nothing         -> SHA1_MD5
        Just hash       -> error ("unimplemented RSA signature hash type: " ++ show hash)
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
        Nothing         -> SHA1_MD5
        Just hash       -> error ("unimplemented ECDSA signature hash type: " ++ show hash)
signatureHashData sig _ = error ("unimplemented signature type: " ++ show sig)

--signatureCreate :: Context -> Maybe HashAndSignatureAlgorithm -> HashDescr -> Bytes -> IO DigitallySigned
signatureCreate :: Context -> Maybe HashAndSignatureAlgorithm -> CertVerifyData -> IO DigitallySigned
signatureCreate ctx malg (hashAlg, toSign) = do
    cc <- usingState_ ctx $ isClientContext
    let signData =
            case (malg, hashAlg) of
                (Nothing, SHA1_MD5) -> hashFinal $ hashUpdate (hashInit SHA1_MD5) toSign
                _                   -> toSign
    DigitallySigned malg <$> signRSA ctx cc hashAlg signData

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
        SignatureRSA   -> verifyRSA ctx cc hashDescr toVerify bs
        SignatureDSS   -> verifyRSA ctx cc hashDescr toVerify bs
        SignatureECDSA -> verifyRSA ctx cc hashDescr toVerify bs
        _              -> error "signature verification not implemented yet"

digitallySignParams :: Context -> Bytes -> SignatureAlgorithm -> IO DigitallySigned
digitallySignParams ctx signatureData sigAlg = do
    usedVersion <- usingState_ ctx getVersion
    let mhash = case usedVersion of
                    TLS12 -> case filter ((==) sigAlg . snd) $ supportedHashSignatures $ ctxSupported ctx of
                                []  -> error ("no hash signature for " ++ show sigAlg)
                                x:_ -> Just (fst x)
                    _     -> Nothing
    let hashDescr = signatureHashData sigAlg mhash
    signatureCreate ctx (fmap (\h -> (h, sigAlg)) mhash) (hashDescr, signatureData)

digitallySignDHParams :: Context
                      -> ServerDHParams
                      -> SignatureAlgorithm
                      -> IO DigitallySigned
digitallySignDHParams ctx serverParams sigAlg = do
    dhParamsData <- withClientAndServerRandom ctx $ encodeSignedDHParams serverParams
    digitallySignParams ctx dhParamsData sigAlg

digitallySignECDHParams :: Context
                        -> ServerECDHParams
                        -> SignatureAlgorithm
                        -> IO DigitallySigned
digitallySignECDHParams ctx serverParams sigAlg = do
    ecdhParamsData <- withClientAndServerRandom ctx $ encodeSignedECDHParams serverParams
    digitallySignParams ctx ecdhParamsData sigAlg

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
