{-# LANGUAGE CPP #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Network.TLS.Credentials (
    Credential,
    Credentials (..),
    credentialLoadX509,
    credentialLoadX509FromMemory,
    credentialLoadX509Chain,
    credentialLoadX509ChainFromMemory,
    credentialsFindForSigning,
    credentialsFindForDecrypting,
    credentialsListSigningAlgorithms,
    credentialPublicPrivateKeys,
    credentialMatchesHashSignatures,
) where

import Data.X509
import qualified Data.X509 as X509
import Data.X509.File
import Data.X509.Memory

import Network.TLS.Crypto
import Network.TLS.Imports
import qualified Network.TLS.Struct as TLS
import Network.TLS.X509

type Credential = (CertificateChain, PrivKey)

newtype Credentials = Credentials [Credential] deriving (Show)

instance Semigroup Credentials where
    Credentials l1 <> Credentials l2 = Credentials (l1 ++ l2)

instance Monoid Credentials where
    mempty = Credentials []
#if !(MIN_VERSION_base(4,11,0))
    mappend (Credentials l1) (Credentials l2) = Credentials (l1 ++ l2)
#endif

-- | try to create a new credential object from a public certificate
-- and the associated private key that are stored on the filesystem
-- in PEM format.
credentialLoadX509
    :: FilePath
    -- ^ public certificate (X.509 format)
    -> FilePath
    -- ^ private key associated
    -> IO (Either String Credential)
credentialLoadX509 certFile = credentialLoadX509Chain certFile []

-- | similar to 'credentialLoadX509' but take the certificate
-- and private key from memory instead of from the filesystem.
credentialLoadX509FromMemory
    :: ByteString
    -> ByteString
    -> Either String Credential
credentialLoadX509FromMemory certData =
    credentialLoadX509ChainFromMemory certData []

-- | similar to 'credentialLoadX509' but also allow specifying chain
-- certificates.
credentialLoadX509Chain
    :: FilePath
    -- ^ public certificate (X.509 format)
    -> [FilePath]
    -- ^ chain certificates (X.509 format)
    -> FilePath
    -- ^ private key associated
    -> IO (Either String Credential)
credentialLoadX509Chain certFile chainFiles privateFile = do
    x509 <- readSignedObject certFile
    chains <- mapM readSignedObject chainFiles
    keys <- readKeyFile privateFile
    case keys of
        [] -> return $ Left "no keys found"
        (k : _) -> return $ Right (CertificateChain . concat $ x509 : chains, k)

-- | similar to 'credentialLoadX509FromMemory' but also allow
-- specifying chain certificates.
credentialLoadX509ChainFromMemory
    :: ByteString
    -> [ByteString]
    -> ByteString
    -> Either String Credential
credentialLoadX509ChainFromMemory certData chainData privateData =
    let x509 = readSignedObjectFromMemory certData
        chains = map readSignedObjectFromMemory chainData
        keys = readKeyFileFromMemory privateData
     in case keys of
            [] -> Left "no keys found"
            (k : _) -> Right (CertificateChain . concat $ x509 : chains, k)

credentialsListSigningAlgorithms :: Credentials -> [KeyExchangeSignatureAlg]
credentialsListSigningAlgorithms (Credentials l) = mapMaybe credentialCanSign l

credentialsFindForSigning
    :: KeyExchangeSignatureAlg -> Credentials -> Maybe Credential
credentialsFindForSigning kxsAlg (Credentials l) = find forSigning l
  where
    forSigning cred = case credentialCanSign cred of
        Nothing -> False
        Just kxs -> kxs == kxsAlg

credentialsFindForDecrypting :: Credentials -> Maybe Credential
credentialsFindForDecrypting (Credentials l) = find forEncrypting l
  where
    forEncrypting cred = Just () == credentialCanDecrypt cred

-- here we assume that only RSA is supported for key encipherment (encryption/decryption)
-- we keep the same construction as 'credentialCanSign', returning a Maybe of () in case
-- this change in future.
credentialCanDecrypt :: Credential -> Maybe ()
credentialCanDecrypt (chain, priv) =
    case (pub, priv) of
        (PubKeyRSA _, PrivKeyRSA _) ->
            case extensionGet (certExtensions cert) of
                Nothing -> Just ()
                Just (ExtKeyUsage flags)
                    | KeyUsage_keyEncipherment `elem` flags -> Just ()
                    | otherwise -> Nothing
        _ -> Nothing
  where
    cert = getCertificate signed
    pub = certPubKey cert
    signed = getCertificateChainLeaf chain

credentialCanSign :: Credential -> Maybe KeyExchangeSignatureAlg
credentialCanSign (chain, priv) =
    case extensionGet (certExtensions cert) of
        Nothing -> findKeyExchangeSignatureAlg (pub, priv)
        Just (ExtKeyUsage flags)
            | KeyUsage_digitalSignature `elem` flags ->
                findKeyExchangeSignatureAlg (pub, priv)
            | otherwise -> Nothing
  where
    cert = getCertificate signed
    pub = certPubKey cert
    signed = getCertificateChainLeaf chain

credentialPublicPrivateKeys :: Credential -> (PubKey, PrivKey)
credentialPublicPrivateKeys (chain, priv) = pub `seq` (pub, priv)
  where
    cert = getCertificate signed
    pub = certPubKey cert
    signed = getCertificateChainLeaf chain

getHashSignature :: SignedCertificate -> Maybe TLS.SignatureScheme
getHashSignature signed =
    case signedAlg $ getSigned signed of
        SignatureALG hashAlg PubKeyALG_RSA -> rsa hashAlg
        SignatureALG hashAlg PubKeyALG_DSA -> dsa hashAlg
        SignatureALG hashAlg PubKeyALG_EC -> ecdsa hashAlg
        SignatureALG X509.HashSHA256 PubKeyALG_RSAPSS -> Just TLS.RSA_PSS_RSAE_SHA256
        SignatureALG X509.HashSHA384 PubKeyALG_RSAPSS -> Just TLS.RSA_PSS_RSAE_SHA384
        SignatureALG X509.HashSHA512 PubKeyALG_RSAPSS -> Just TLS.RSA_PSS_RSAE_SHA512
        SignatureALG_IntrinsicHash PubKeyALG_Ed25519 -> Just TLS.ED25519
        SignatureALG_IntrinsicHash PubKeyALG_Ed448 -> Just TLS.ED448
        SignatureALG_IntrinsicHash PubKeyALG_MLDSA44 -> Just TLS.MLDSA44
        SignatureALG_IntrinsicHash PubKeyALG_MLDSA65 -> Just TLS.MLDSA65
        SignatureALG_IntrinsicHash PubKeyALG_MLDSA87 -> Just TLS.MLDSA87
        _ -> Nothing
  where
    -- A certificate can be signed with a combination TLS 1.2 allowed and
    -- the registry never named as a scheme, MD5 and SHA-224 among them, so
    -- those have names here too.
    rsa X509.HashMD5 = Just TLS.RSA_PKCS1_MD5
    rsa X509.HashSHA1 = Just TLS.RSA_PKCS1_SHA1
    rsa X509.HashSHA224 = Just TLS.RSA_PKCS1_SHA224
    rsa X509.HashSHA256 = Just TLS.RSA_PKCS1_SHA256
    rsa X509.HashSHA384 = Just TLS.RSA_PKCS1_SHA384
    rsa X509.HashSHA512 = Just TLS.RSA_PKCS1_SHA512
    rsa _ = Nothing

    dsa X509.HashMD5 = Just TLS.DSA_MD5
    dsa X509.HashSHA1 = Just TLS.DSA_SHA1
    dsa X509.HashSHA224 = Just TLS.DSA_SHA224
    dsa X509.HashSHA256 = Just TLS.DSA_SHA256
    dsa X509.HashSHA384 = Just TLS.DSA_SHA384
    dsa X509.HashSHA512 = Just TLS.DSA_SHA512
    dsa _ = Nothing

    ecdsa X509.HashMD5 = Just TLS.ECDSA_MD5
    ecdsa X509.HashSHA1 = Just TLS.ECDSA_SHA1
    ecdsa X509.HashSHA224 = Just TLS.ECDSA_SHA224
    ecdsa X509.HashSHA256 = Just TLS.ECDSA_SECP256R1_SHA256
    ecdsa X509.HashSHA384 = Just TLS.ECDSA_SECP384R1_SHA384
    ecdsa X509.HashSHA512 = Just TLS.ECDSA_SECP521R1_SHA512
    ecdsa _ = Nothing

-- | Checks whether certificate signatures in the chain comply with a list of
-- hash/signature algorithm pairs.  Currently the verification applies only to
-- the signature of the leaf certificate, and when not self-signed.  This may
-- be extended to additional chain elements in the future.
credentialMatchesHashSignatures
    :: [TLS.SignatureScheme] -> Credential -> Bool
credentialMatchesHashSignatures hashSigs (chain, _) =
    case chain of
        CertificateChain [] -> True
        CertificateChain (leaf : _) -> isSelfSigned leaf || matchHashSig leaf
  where
    matchHashSig signed = case getHashSignature signed of
        Nothing -> False
        Just hs -> hs `elem` hashSigs

    isSelfSigned signed =
        let cert = getCertificate signed
         in certSubjectDN cert == certIssuerDN cert
