{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Network.TLS.Handshake.Signature
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.Signature
    ( getHashAndASN1
    , prepareCertificateVerifySignatureData
    , signatureHashData
    , signatureCreate
    , signatureVerify
    , signatureVerifyWithHashDescr
    , generateSignedDHParams
    , generateSignedECDHParams
    ) where

import Crypto.PubKey.HashDescr
import Network.TLS.Crypto
import Network.TLS.Context.Internal
import Network.TLS.Struct
import Network.TLS.Packet (generateCertificateVerify_SSL, encodeSignedDHParams, encodeSignedECDHParams)
import Network.TLS.State
import Network.TLS.Handshake.State
import Network.TLS.Handshake.Key
import Network.TLS.Util

import Control.Applicative
import Control.Monad.State

getHashAndASN1 :: MonadIO m => (HashAlgorithm, SignatureAlgorithm) -> m HashDescr
getHashAndASN1 hashSig = case hashSig of
    (HashSHA1,   SignatureRSA) -> return hashDescrSHA1
    (HashSHA224, SignatureRSA) -> return hashDescrSHA224
    (HashSHA256, SignatureRSA) -> return hashDescrSHA256
    (HashSHA384, SignatureRSA) -> return hashDescrSHA384
    (HashSHA512, SignatureRSA) -> return hashDescrSHA512
    _                          -> throwCore $ Error_Misc "unsupported hash/sig algorithm"

prepareCertificateVerifySignatureData :: Context
                                      -> Version
                                      -> Maybe HashAndSignatureAlgorithm
                                      -> Bytes
                                      -> IO (HashDescr, Bytes)
prepareCertificateVerifySignatureData ctx usedVersion malg msgs
    | usedVersion == SSL3 = do
        Just masterSecret <- usingHState ctx $ gets hstMasterSecret
        let digest = generateCertificateVerify_SSL masterSecret (hashUpdate (hashInit SHA1_MD5) msgs)
            hsh = HashDescr id id
        return (hsh, digest)
    | usedVersion == TLS10 || usedVersion == TLS11 = do
        let hashf bs = hashFinal (hashUpdate (hashInit SHA1_MD5) bs)
            hsh = HashDescr hashf id
        return (hsh, msgs)
    | otherwise = do
        let Just hashSig = malg
        hsh <- getHashAndASN1 hashSig
        return (hsh, msgs)

signatureHashData :: SignatureAlgorithm -> Maybe HashAlgorithm -> HashDescr
signatureHashData SignatureRSA mhash =
    case mhash of
        Just HashSHA512 -> hashDescrSHA512
        Just HashSHA256 -> hashDescrSHA256
        Just HashSHA1   -> hashDescrSHA1
        Nothing         -> HashDescr (hashFinal . hashUpdate (hashInit SHA1_MD5)) id
        _               -> error ("unimplemented signature hash type")
signatureHashData SignatureDSS mhash =
    case mhash of
        Nothing       -> hashDescrSHA1
        Just HashSHA1 -> hashDescrSHA1
        Just _        -> error "invalid DSA hash choice, only SHA1 allowed"
signatureHashData sig _ = error ("unimplemented signature type: " ++ show sig)

signatureCreate :: Context -> Maybe HashAndSignatureAlgorithm -> HashDescr -> Bytes -> IO DigitallySigned
signatureCreate ctx malg hashMethod toSign = do
    cc <- usingState_ ctx $ isClientContext
    DigitallySigned malg <$> signRSA ctx cc hashMethod toSign

signatureVerify :: Context -> SignatureAlgorithm -> Bytes -> DigitallySigned -> IO Bool
signatureVerify ctx sigAlgExpected toVerify digSig@(DigitallySigned hashSigAlg _) = do
    usedVersion <- usingState_ ctx getVersion
    let hashDescr = case (usedVersion, hashSigAlg) of
            (TLS12, Nothing)    -> error "expecting hash and signature algorithm in a TLS12 digitally signed structure"
            (TLS12, Just (h,s)) | s == sigAlgExpected -> signatureHashData sigAlgExpected (Just h)
                                | otherwise           -> error "expecting different signature algorithm"
            (_,     Nothing)    -> signatureHashData sigAlgExpected Nothing
            (_,     Just _)     -> error "not expecting hash and signature algorithm in a < TLS12 digitially signed structure"
    signatureVerifyWithHashDescr ctx sigAlgExpected hashDescr toVerify digSig

signatureVerifyWithHashDescr :: Context
                             -> SignatureAlgorithm
                             -> HashDescr
                             -> Bytes
                             -> DigitallySigned
                             -> IO Bool
signatureVerifyWithHashDescr ctx sigAlgExpected hashDescr toVerify (DigitallySigned _ bs) = do
    cc <- usingState_ ctx $ isClientContext
    case sigAlgExpected of
        SignatureRSA -> verifyRSA ctx cc hashDescr toVerify bs
        SignatureDSS -> verifyRSA ctx cc hashDescr toVerify bs
        _            -> error "not implemented yet"

generateSignedDHParams :: Context -> ServerDHParams -> IO Bytes
generateSignedDHParams ctx serverParams = do
    (cran, sran) <- usingHState ctx $ do
                        (,) <$> gets hstClientRandom <*> (fromJust "server random" <$> gets hstServerRandom)
    return $ encodeSignedDHParams cran sran serverParams

generateSignedECDHParams :: Context -> ServerECDHParams -> IO Bytes
generateSignedECDHParams ctx serverParams = do
    (cran, sran) <- usingHState ctx $ do
                        (,) <$> gets hstClientRandom <*> (fromJust "server random" <$> gets hstServerRandom)
    return $ encodeSignedECDHParams cran sran serverParams
