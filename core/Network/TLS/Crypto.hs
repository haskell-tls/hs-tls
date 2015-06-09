{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE ExistentialQuantification #-}
module Network.TLS.Crypto
    ( HashContext
    , HashCtx
    , hashInit
    , hashUpdate
    , hashUpdateSSL
    , hashFinal

    , module Network.TLS.Crypto.DH
    , module Network.TLS.Crypto.ECDH

    -- * Hash
    , hash
    , Hash(..)
    , hashName
    , hashDigestSize
    , hashBlockSize

    -- * key exchange generic interface
    , PubKey(..)
    , PrivKey(..)
    , PublicKey
    , PrivateKey
    , HashDescr(..)
    , kxEncrypt
    , kxDecrypt
    , kxSign
    , kxVerify
    , KxError(..)
    ) where

import qualified Crypto.Hash as H
import qualified Data.ByteString as B
import qualified Data.Byteable as B
import Data.ByteString (ByteString)
import Crypto.PubKey.HashDescr
import Crypto.Random
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA

import qualified Data.ByteString as B
import Data.ByteString (ByteString)
import Data.X509 (PrivKey(..), PubKey(..))
import Network.TLS.Crypto.DH
import Network.TLS.Crypto.ECDH

import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding (DER(..), BER(..))

{-# DEPRECATED PublicKey "use PubKey" #-}
type PublicKey = PubKey
{-# DEPRECATED PrivateKey "use PrivKey" #-}
type PrivateKey = PrivKey

data KxError =
      RSAError RSA.Error
    | KxUnsupported
    deriving (Show)

-- functions to use the hidden class.
hashInit :: Hash -> HashContext
hashInit MD5      = HashContext $ ContextSimple (H.hashInit :: H.Context H.MD5)
hashInit SHA1     = HashContext $ ContextSimple (H.hashInit :: H.Context H.SHA1)
hashInit SHA256   = HashContext $ ContextSimple (H.hashInit :: H.Context H.SHA256)
hashInit SHA512   = HashContext $ ContextSimple (H.hashInit :: H.Context H.SHA512)
hashInit SHA1_MD5 = HashContextSSL H.hashInit H.hashInit

hashUpdate :: HashContext -> B.ByteString -> HashCtx
hashUpdate (HashContext (ContextSimple h)) b = HashContext $ ContextSimple (H.hashUpdate h b)
hashUpdate (HashContextSSL sha1Ctx md5Ctx) b =
    HashContextSSL (H.hashUpdate sha1Ctx b) (H.hashUpdate md5Ctx b)

hashUpdateSSL :: HashCtx
              -> (B.ByteString,B.ByteString) -- ^ (for the md5 context, for the sha1 context)
              -> HashCtx
hashUpdateSSL (HashContext _) _ = error "internal error: update SSL without a SSL Context"
hashUpdateSSL (HashContextSSL sha1Ctx md5Ctx) (b1,b2) =
    HashContextSSL (H.hashUpdate sha1Ctx b2) (H.hashUpdate md5Ctx b1)

hashFinal :: HashCtx -> B.ByteString
hashFinal (HashContext (ContextSimple h)) = B.toBytes $ H.hashFinalize h
hashFinal (HashContextSSL sha1Ctx md5Ctx) =
    B.concat [B.toBytes (H.hashFinalize md5Ctx), B.toBytes (H.hashFinalize sha1Ctx)]

data Hash = MD5 | SHA1 | SHA256 | SHA512 | SHA1_MD5
    deriving (Show,Eq)

data HashContext =
      HashContext ContextSimple
    | HashContextSSL (H.Context H.SHA1) (H.Context H.MD5)

instance Show HashContext where
    show _ = "hash-context"

data ContextSimple = forall alg . H.HashAlgorithm alg => ContextSimple (H.Context alg)

type HashCtx = HashContext

hash :: Hash -> B.ByteString -> B.ByteString
hash MD5 b      = B.toBytes . (H.hash :: B.ByteString -> H.Digest H.MD5) $ b
hash SHA1 b     = B.toBytes . (H.hash :: B.ByteString -> H.Digest H.SHA1) $ b
hash SHA256 b   = B.toBytes . (H.hash :: B.ByteString -> H.Digest H.SHA256) $ b
hash SHA512 b   = B.toBytes . (H.hash :: B.ByteString -> H.Digest H.SHA512) $ b
hash SHA1_MD5 b =
    B.concat [B.toBytes (md5Hash b), B.toBytes (sha1Hash b)]
  where
    sha1Hash :: B.ByteString -> H.Digest H.SHA1
    sha1Hash = H.hash
    md5Hash :: B.ByteString -> H.Digest H.MD5
    md5Hash = H.hash

hashName :: Hash -> String
hashName = show

hashDigestSize :: Hash -> Int
hashDigestSize MD5    = 16
hashDigestSize SHA1   = 20
hashDigestSize SHA256 = 32
hashDigestSize SHA512 = 64
hashDigestSize SHA1_MD5 = 36

hashBlockSize :: Hash -> Int
hashBlockSize MD5    = 64
hashBlockSize SHA1   = 64
hashBlockSize SHA256 = 64
hashBlockSize SHA512 = 128
hashBlockSize SHA1_MD5 = 64

{- key exchange methods encrypt and decrypt for each supported algorithm -}

generalizeRSAWithRNG :: Either RSA.Error a -> Either KxError a
generalizeRSAWithRNG (Left e)  = Left (RSAError e)
generalizeRSAWithRNG (Right x) = Right x

kxEncrypt :: MonadRandom r => PublicKey -> ByteString -> r (Either KxError ByteString)
kxEncrypt (PubKeyRSA pk) b = generalizeRSAWithRNG `fmap` RSA.encrypt pk b
kxEncrypt _              _ = return (Left KxUnsupported)

kxDecrypt :: MonadRandom r => PrivateKey -> ByteString -> r (Either KxError ByteString)
kxDecrypt (PrivKeyRSA pk) b = generalizeRSAWithRNG `fmap` RSA.decryptSafer pk b
kxDecrypt _               _ = return (Left KxUnsupported)

-- Verify that the signature matches the given message, using the
-- public key.
--
kxVerify :: PublicKey -> HashDescr -> ByteString -> ByteString -> Bool
kxVerify (PubKeyRSA pk) hashDescr msg sign = RSA.verify hashDescr pk msg sign
kxVerify (PubKeyDSA pk) hashDescr msg signBS =
    case signature of
        Right (sig, []) -> DSA.verify (hashFunction hashDescr) pk sig msg
        _               -> False
  where signature = case decodeASN1' BER signBS of
                        Left err    -> Left (show err)
                        Right asn1s -> fromASN1 asn1s
kxVerify _              _         _   _    = False

-- Sign the given message using the private key.
--
kxSign :: MonadRandom r
       => PrivateKey
       -> HashDescr
       -> ByteString
       -> r (Either KxError ByteString)
kxSign (PrivKeyRSA pk) hashDescr msg =
    generalizeRSAWithRNG $ RSA.signSafer g hashDescr pk msg
kxSign (PrivKeyDSA pk) hashDescr msg =
    sign <- DSA.sign pk (hashFunction hashDescr) msg
    return (Right $ encodeASN1' DER $ toASN1 sign [])
--kxSign g _               _         _   =
--    (Left KxUnsupported, g)
