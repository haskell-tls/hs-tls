{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE ExistentialQuantification #-}
module Network.TLS.Crypto
        ( HashCtx(..)
        , hashInit
        , hashUpdate
        , hashUpdateSSL
        , hashFinal

        -- * constructor
        , hashMD5SHA1
        , hashSHA256

        -- * key exchange generic interface
        , PublicKey(..)
        , PrivateKey(..)
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
import qualified Crypto.Cipher.RSA as RSA
import Crypto.Random (CryptoRandomGen)

data PublicKey = PubRSA RSA.PublicKey

data PrivateKey = PrivRSA RSA.PrivateKey

instance Show PublicKey where
        show (_) = "PublicKey(..)"

instance Show PrivateKey where
        show (_) = "privateKey(..)"

data KxError = RSAError RSA.Error
        deriving (Show)

data KeyXchg =
          KxRSA RSA.PublicKey RSA.PrivateKey
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

data HashSHA256 = HashSHA256 SHA256.Ctx

instance HashCtxC HashSHA256 where
        hashCName _                    = "SHA256"
        hashCInit _                    = HashSHA256 SHA256.init
        hashCUpdate (HashSHA256 ctx) b = HashSHA256 (SHA256.update ctx b)
        hashCUpdateSSL _ _             = undefined
        hashCFinal  (HashSHA256 ctx)   = SHA256.finalize ctx

-- functions to use the hidden class.
hashInit :: HashCtx -> HashCtx
hashInit   (HashCtx h)   = HashCtx $ hashCInit h

hashUpdate :: HashCtx -> B.ByteString -> HashCtx
hashUpdate (HashCtx h) b = HashCtx $ hashCUpdate h b

hashUpdateSSL :: HashCtx -> (B.ByteString,B.ByteString) -> HashCtx
hashUpdateSSL (HashCtx h) bs = HashCtx $ hashCUpdateSSL h bs

hashFinal :: HashCtx -> B.ByteString
hashFinal  (HashCtx h)   = hashCFinal h

-- real hash constructors
hashMD5SHA1, hashSHA256 :: HashCtx
hashMD5SHA1 = HashCtx (HashMD5SHA1 SHA1.init MD5.init)
hashSHA256  = HashCtx (HashSHA256 SHA256.init)

{- key exchange methods encrypt and decrypt for each supported algorithm -}
generalizeRSAError :: Either RSA.Error a -> Either KxError a
generalizeRSAError (Left e)  = Left (RSAError e)
generalizeRSAError (Right x) = Right x

kxEncrypt :: CryptoRandomGen g => g -> PublicKey -> ByteString -> Either KxError (ByteString, g)
kxEncrypt g (PubRSA pk) b = generalizeRSAError $ RSA.encrypt g pk b

kxDecrypt :: PrivateKey -> ByteString -> Either KxError ByteString
kxDecrypt (PrivRSA pk) b  = generalizeRSAError $ RSA.decrypt pk b

kxVerify :: PublicKey -> ByteString -> ByteString -> Either KxError Bool
kxVerify (PubRSA pk) b sign = 
  let hashF = SHA1.hash
      hashASN1 = B.empty
  in generalizeRSAError $ RSA.verify hashF hashASN1 pk b sign

kxSign :: PrivateKey -> ByteString -> Either KxError ByteString
kxSign (PrivRSA pk) b  = 
  let hashF = SHA1.hash
      hashASN1 = B.empty
  in generalizeRSAError $ RSA.sign hashF hashASN1 pk b
