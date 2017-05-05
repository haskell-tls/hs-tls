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
    , credentialLoadX509Chain
    , credentialLoadX509ChainFromMemory
    , credentialsFindForSigning
    , credentialsFindForDecrypting
    , credentialsListSigningAlgorithms
    ) where

import Data.ByteString (ByteString)
import Data.Monoid
import Data.Maybe (catMaybes)
import Data.List (find)
import Network.TLS.Crypto.Types
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
credentialLoadX509 certFile = credentialLoadX509Chain certFile []

-- | similar to 'credentialLoadX509' but take the certificate
-- and private key from memory instead of from the filesystem.
credentialLoadX509FromMemory :: ByteString
                  -> ByteString
                  -> Either String Credential
credentialLoadX509FromMemory certData =
  credentialLoadX509ChainFromMemory certData []

-- | similar to 'credentialLoadX509' but also allow specifying chain
-- certificates.
credentialLoadX509Chain ::
                      FilePath   -- ^ public certificate (X.509 format)
                   -> [FilePath] -- ^ chain certificates (X.509 format)
                   -> FilePath   -- ^ private key associated
                   -> IO (Either String Credential)
credentialLoadX509Chain certFile chainFiles privateFile = do
    x509 <- readSignedObject certFile
    chains <- mapM readSignedObject chainFiles
    keys <- readKeyFile privateFile
    case keys of
        []    -> return $ Left "no keys found"
        (k:_) -> return $ Right (CertificateChain . concat $ x509 : chains, k)

-- | similar to 'credentialLoadX509FromMemory' but also allow
-- specifying chain certificates.
credentialLoadX509ChainFromMemory :: ByteString
                  -> [ByteString]
                  -> ByteString
                  -> Either String Credential
credentialLoadX509ChainFromMemory certData chainData privateData = do
    let x509   = readSignedObjectFromMemory certData
        chains = map readSignedObjectFromMemory chainData
        keys   = readKeyFileFromMemory privateData
     in case keys of
            []    -> Left "no keys found"
            (k:_) -> Right (CertificateChain . concat $ x509 : chains, k)

credentialsListSigningAlgorithms :: Credentials -> [DigitalSignatureAlg]
credentialsListSigningAlgorithms (Credentials l) = catMaybes $ map credentialCanSign l

credentialsFindForSigning :: DigitalSignatureAlg -> Credentials -> Maybe (CertificateChain, PrivKey)
credentialsFindForSigning sigAlg (Credentials l) = find forSigning l
  where forSigning cred = case credentialCanSign cred of
            Nothing  -> False
            Just sig -> sig == sigAlg

credentialsFindForDecrypting :: Credentials -> Maybe (CertificateChain, PrivKey)
credentialsFindForDecrypting (Credentials l) = find forEncrypting l
  where forEncrypting cred = Just () == credentialCanDecrypt cred

-- here we assume that only RSA is supported for key encipherment (encryption/decryption)
-- we keep the same construction as 'credentialCanSign', returning a Maybe of () in case
-- this change in future.
credentialCanDecrypt :: Credential -> Maybe ()
credentialCanDecrypt (chain, priv) =
    case (pub, priv) of
        (PubKeyRSA _, PrivKeyRSA _) ->
            case extensionGet (certExtensions cert) of
                Nothing                                     -> Just ()
                Just (ExtKeyUsage flags)
                    | KeyUsage_keyEncipherment `elem` flags -> Just ()
                    | otherwise                             -> Nothing
        _                           -> Nothing
    where cert   = signedObject $ getSigned signed
          pub    = certPubKey cert
          signed = getCertificateChainLeaf chain

credentialCanSign :: Credential -> Maybe DigitalSignatureAlg
credentialCanSign (chain, priv) =
    case extensionGet (certExtensions cert) of
        Nothing    -> getSignatureAlg pub priv
        Just (ExtKeyUsage flags)
            | KeyUsage_digitalSignature `elem` flags -> getSignatureAlg pub priv
            | otherwise                              -> Nothing
    where cert   = signedObject $ getSigned signed
          pub    = certPubKey cert
          signed = getCertificateChainLeaf chain

getSignatureAlg :: PubKey -> PrivKey -> Maybe DigitalSignatureAlg
getSignatureAlg pub priv =
    case (pub, priv) of
        (PubKeyRSA _, PrivKeyRSA _)     -> Just RSA
        (PubKeyDSA _, PrivKeyDSA _)     -> Just DSS
        --(PubKeyECDSA _, PrivKeyECDSA _) -> Just ECDSA
        _                               -> Nothing
