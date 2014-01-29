-- |
-- Module      : Network.TLS.Credentials
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Credentials
    ( Credential
    , Credentials(..)
    , credentialLoadX509
    , credentialLoadX509FromMemory
    , credentialsFindForSigning
    , credentialsFindForDecrypting
    , credentialsListSigningAlgorithms
    ) where

import Data.Monoid
import Data.Maybe (catMaybes)
import Data.List (find)
import Network.TLS.Struct
import Network.TLS.X509
import Data.X509.File
import Data.X509.Memory
import Data.X509

type Credential = (CertificateChain, PrivKey)

newtype Credentials = Credentials [Credential]

instance Monoid Credentials where
    mempty = Credentials []
    mappend (Credentials l1) (Credentials l2) = Credentials (l1 ++ l2)

-- | try to create a new credential object from a public certificate
-- and the associated private key that are stored on the filesystem
-- in PEM format.
credentialLoadX509 :: FilePath -- ^ public certificate (X.509 format)
                   -> FilePath -- ^ private key associated
                   -> IO (Either String Credential)
credentialLoadX509 certFile privateFile = do
    x509 <- readSignedObject certFile
    keys <- readKeyFile privateFile
    case keys of
        []    -> return $ Left "no keys found"
        (k:_) -> return $ Right (CertificateChain x509, k)

-- | similar to 'credentialLoadX509' but take the certificate
-- and private key from memory instead of from the filesystem.
credentialLoadX509FromMemory :: Bytes
                  -> Bytes
                  -> Either String Credential
credentialLoadX509FromMemory certData privateData = do
    let x509 = readSignedObjectFromMemory certData
        keys = readKeyFileFromMemory privateData
     in case keys of
            []    -> Left "no keys found"
            (k:_) -> Right (CertificateChain x509, k)
  where

credentialsListSigningAlgorithms :: Credentials -> [SignatureAlgorithm]
credentialsListSigningAlgorithms (Credentials l) = catMaybes $ map credentialCanSign l

credentialsFindForSigning :: SignatureAlgorithm -> Credentials -> Maybe (CertificateChain, PrivKey)
credentialsFindForSigning sigAlg (Credentials l) = find forSigning l
  where forSigning cred = Just sigAlg == credentialCanSign cred

credentialsFindForDecrypting :: Credentials -> Maybe (CertificateChain, PrivKey)
credentialsFindForDecrypting (Credentials l) = find forEncrypting l
  where forEncrypting cred = Just () == credentialCanDecrypt cred

-- here we assume that only RSA is supported for key encipherment (encryption/decryption)
-- we keep the same construction as 'credentialCanSign', returning a Maybe of () in case
-- this change in future.
credentialCanDecrypt :: Credential -> Maybe ()
credentialCanDecrypt (chain, priv) =
    case extensionGet (certExtensions cert) of
        Nothing    -> Just ()
        Just (ExtKeyUsage flags)
            | KeyUsage_keyEncipherment `elem` flags ->
                case (pub, priv) of
                    (PubKeyRSA _, PrivKeyRSA _) -> Just ()
                    _                           -> Nothing
            | otherwise                         -> Nothing
    where cert   = signedObject $ getSigned signed
          pub    = certPubKey cert
          signed = getCertificateChainLeaf chain

credentialCanSign :: Credential -> Maybe SignatureAlgorithm
credentialCanSign (chain, priv) =
    case extensionGet (certExtensions cert) of
        Nothing    -> getSignatureAlg pub priv
        Just (ExtKeyUsage flags)
            | KeyUsage_digitalSignature `elem` flags -> getSignatureAlg pub priv
            | otherwise                              -> Nothing
    where cert   = signedObject $ getSigned signed
          pub    = certPubKey cert
          signed = getCertificateChainLeaf chain

getSignatureAlg :: PubKey -> PrivKey -> Maybe SignatureAlgorithm
getSignatureAlg pub priv =
    case (pub, priv) of
        (PubKeyRSA _, PrivKeyRSA _)     -> Just SignatureRSA
        (PubKeyDSA _, PrivKeyDSA _)     -> Just SignatureDSS
        --(PubKeyECDSA _, PrivKeyECDSA _) -> Just SignatureECDSA
        _                               -> Nothing
