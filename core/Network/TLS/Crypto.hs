{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE ExistentialQuantification #-}
module Network.TLS.Crypto
    ( HashCtx(..)
    , hashInit
    , hashUpdate
    , hashUpdateSSL
    , hashFinal

    , module Network.TLS.Crypto.DH

    -- * constructor
    , hashMD5SHA1
    , hashSHA1
    , hashSHA256

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

import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.MD5 as MD5
import qualified Data.ByteString as B
import Data.ByteString (ByteString)
import Crypto.PubKey.HashDescr
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import Crypto.Random
import Data.X509 (PrivKey(..), PubKey(..))

{-# DEPRECATED PublicKey "use PubKey" #-}
type PublicKey = PubKey
{-# DEPRECATED PrivateKey "use PrivKey" #-}
type PrivateKey = PrivKey

data KxError =
      RSAError RSA.Error
    | KxUnsupported
    deriving (Show)

class HashCtxC a where
    hashCName      :: a -> String
    hashCInit      :: a -> a
    hashCUpdate    :: a -> B.ByteString -> a
    hashCUpdateSSL :: a -> (B.ByteString,B.ByteString) -> a
    hashCFinal     :: a -> B.ByteString

data HashCtx = forall h . HashCtxC h => HashCtx h

instance Show HashCtx where
    show (HashCtx c) = hashCName c

{- MD5 & SHA1 joined -}
data HashMD5SHA1 = HashMD5SHA1 SHA1.Ctx MD5.Ctx

instance HashCtxC HashMD5SHA1 where
    hashCName _                  = "MD5-SHA1"
    hashCInit _                  = HashMD5SHA1 SHA1.init MD5.init
    hashCUpdate (HashMD5SHA1 sha1ctx md5ctx) b = HashMD5SHA1 (SHA1.update sha1ctx b) (MD5.update md5ctx b)
    hashCUpdateSSL (HashMD5SHA1 sha1ctx md5ctx) (b1,b2) = HashMD5SHA1 (SHA1.update sha1ctx b2) (MD5.update md5ctx b1)
    hashCFinal  (HashMD5SHA1 sha1ctx md5ctx)   = B.concat [MD5.finalize md5ctx, SHA1.finalize sha1ctx]

newtype HashSHA1 = HashSHA1 SHA1.Ctx

instance HashCtxC HashSHA1 where
    hashCName _                  = "SHA1"
    hashCInit _                  = HashSHA1 SHA1.init
    hashCUpdate (HashSHA1 ctx) b = HashSHA1 (SHA1.update ctx b)
    hashCUpdateSSL (HashSHA1 ctx) (_,b2) = HashSHA1 (SHA1.update ctx b2)
    hashCFinal  (HashSHA1 ctx)   = SHA1.finalize ctx

newtype HashSHA256 = HashSHA256 SHA256.Ctx

instance HashCtxC HashSHA256 where
    hashCName _                    = "SHA256"
    hashCInit _                    = HashSHA256 SHA256.init
    hashCUpdate (HashSHA256 ctx) b = HashSHA256 (SHA256.update ctx b)
    hashCUpdateSSL _ _             = error "CUpdateSSL with HashSHA256"
    hashCFinal  (HashSHA256 ctx)   = SHA256.finalize ctx

-- functions to use the hidden class.
hashInit :: HashCtx -> HashCtx
hashInit   (HashCtx h)   = HashCtx $ hashCInit h

hashUpdate :: HashCtx -> B.ByteString -> HashCtx
hashUpdate (HashCtx h) b = HashCtx $ hashCUpdate h b

hashUpdateSSL :: HashCtx
              -> (B.ByteString,B.ByteString) -- ^ (for the md5 context, for the sha1 context)
              -> HashCtx
hashUpdateSSL (HashCtx h) bs = HashCtx $ hashCUpdateSSL h bs

hashFinal :: HashCtx -> B.ByteString
hashFinal  (HashCtx h)   = hashCFinal h

-- real hash constructors
hashMD5SHA1, hashSHA1, hashSHA256 :: HashCtx
hashMD5SHA1 = HashCtx (HashMD5SHA1 SHA1.init MD5.init)
hashSHA1    = HashCtx (HashSHA1 SHA1.init)
hashSHA256  = HashCtx (HashSHA256 SHA256.init)

{- key exchange methods encrypt and decrypt for each supported algorithm -}

generalizeRSAWithRNG :: CPRG g => (Either RSA.Error a, g) -> (Either KxError a, g)
generalizeRSAWithRNG (Left e, g) = (Left (RSAError e), g)
generalizeRSAWithRNG (Right x, g) = (Right x, g)

kxEncrypt :: CPRG g => g -> PublicKey -> ByteString -> (Either KxError ByteString, g)
kxEncrypt g (PubKeyRSA pk) b = generalizeRSAWithRNG $ RSA.encrypt g pk b
kxEncrypt g _              _ = (Left KxUnsupported, g)

kxDecrypt :: CPRG g => g -> PrivateKey -> ByteString -> (Either KxError ByteString, g)
kxDecrypt g (PrivKeyRSA pk) b = generalizeRSAWithRNG $ RSA.decryptSafer g pk b
kxDecrypt g _               _ = (Left KxUnsupported, g)

-- Verify that the signature matches the given message, using the
-- public key.
--
kxVerify :: PublicKey -> HashDescr -> ByteString -> ByteString -> Bool
kxVerify (PubKeyRSA pk) hashDescr msg sign = RSA.verify hashDescr pk msg sign
kxVerify _              _         _   _    = False

-- Sign the given message using the private key.
--
kxSign :: CPRG g => g -> PrivateKey -> HashDescr -> ByteString -> (Either KxError ByteString, g)
kxSign g (PrivKeyRSA pk) hashDescr msg  =
    generalizeRSAWithRNG $ RSA.signSafer g hashDescr pk msg
kxSign g _               _         _    =
    (Left KxUnsupported, g)
