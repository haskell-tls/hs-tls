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
    , signatureCreate
    , signatureVerify
    ) where

import Crypto.PubKey.HashDescr
import Network.TLS.Crypto
import Network.TLS.Context
import Network.TLS.Struct
import Network.TLS.Packet (generateCertificateVerify_SSL)
import Network.TLS.Handshake.State
import Network.TLS.Handshake.Key

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
        let digest = generateCertificateVerify_SSL masterSecret (hashUpdate (hashInit hashMD5SHA1) msgs)
            hsh = HashDescr id id
        return (hsh, digest)
    | usedVersion == TLS10 || usedVersion == TLS11 = do
        let hashf bs = hashFinal (hashUpdate (hashInit hashMD5SHA1) bs)
            hsh = HashDescr hashf id
        return (hsh, msgs)
    | otherwise = do
        let Just hashSig = malg
        hsh <- getHashAndASN1 hashSig
        return (hsh, msgs)

signatureCreate :: Context -> Maybe HashAndSignatureAlgorithm -> HashDescr -> Bytes -> IO DigitallySigned
signatureCreate ctx malg hashMethod toSign =
    DigitallySigned malg <$> signRSA ctx hashMethod toSign

signatureVerify :: Context -> HashDescr -> Bytes -> DigitallySigned -> IO Bool
signatureVerify ctx hashMethod toVerify (DigitallySigned _ bs) =
    verifyRSA ctx hashMethod toVerify bs
