{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE ExistentialQuantification #-}
module Network.TLS.Crypto
	( HashCtx(..)
	, hashInit
	, hashUpdate
	, hashFinal

	-- * constructor
	, hashSHA1
	, hashMD5
	, hashMD5SHA1

	-- * key exchange generic interface
	, PublicKey(..)
	, PrivateKey(..)
	, kxEncrypt
	, kxDecrypt
	, KxError(..)
	) where

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
	hashCName    :: a -> String
	hashCInit    :: a -> a
	hashCUpdate  :: a -> B.ByteString -> a
	hashCFinal   :: a -> B.ByteString

data HashCtx = forall h . HashCtxC h => HashCtx h

instance Show HashCtx where
	show (HashCtx c) = hashCName c

{- MD5 -}
data HashMD5 = HashMD5 MD5.Ctx

instance HashCtxC HashMD5 where
	hashCName _                 = "MD5"
	hashCInit _                 = HashMD5 MD5.init
	hashCUpdate (HashMD5 ctx) b = HashMD5 (MD5.update ctx b)
	hashCFinal  (HashMD5 ctx)   = MD5.finalize ctx

{- SHA1 -}
data HashSHA1 = HashSHA1 SHA1.Ctx

instance HashCtxC HashSHA1 where
	hashCName _                  = "SHA1"
	hashCInit _                  = HashSHA1 SHA1.init
	hashCUpdate (HashSHA1 ctx) b = HashSHA1 (SHA1.update ctx b)
	hashCFinal  (HashSHA1 ctx)   = SHA1.finalize ctx

{- MD5 & SHA1 joined -}
data HashMD5SHA1 = HashMD5SHA1 SHA1.Ctx MD5.Ctx

instance HashCtxC HashMD5SHA1 where
	hashCName _                  = "MD5-SHA1"
	hashCInit _                  = HashMD5SHA1 SHA1.init MD5.init
	hashCUpdate (HashMD5SHA1 sha1ctx md5ctx) b = HashMD5SHA1 (SHA1.update sha1ctx b) (MD5.update md5ctx b)
	hashCFinal  (HashMD5SHA1 sha1ctx md5ctx)   = B.concat [MD5.finalize md5ctx, SHA1.finalize sha1ctx]

{- MD5 & SHA1 joined specially for old SSL3 -}
{-
data HashMD5SHA1SSL = HashMD5SHA1SSL SHA1.Ctx MD5.Ctx

instance HashCtxC HashMD5SHA1SSL where
	hashCName _                  = "MD5-SHA1-SSL"
	hashCInit _                  = HashMD5SHA1SSL SHA1.init MD5.init
	hashCUpdate (HashMD5SHA1SSL sha1ctx md5ctx) b = HashMD5SHA1SSL (SHA1.update sha1ctx b) (MD5.update md5ctx b)
	hashCFinal  (HashMD5SHA1SSL sha1ctx md5ctx)   =
		B.concat [MD5.finalize md5ctx, SHA1.finalize sha1ctx]
-}

-- functions to use the hidden class.
hashInit :: HashCtx -> HashCtx
hashInit   (HashCtx h)   = HashCtx $ hashCInit h

hashUpdate :: HashCtx -> B.ByteString -> HashCtx
hashUpdate (HashCtx h) b = HashCtx $ hashCUpdate h b

hashFinal :: HashCtx -> B.ByteString
hashFinal  (HashCtx h)   = hashCFinal h

-- real hash constructors
hashSHA1, hashMD5, hashMD5SHA1 :: HashCtx
hashSHA1    = HashCtx (HashSHA1 SHA1.init)
hashMD5     = HashCtx (HashMD5 MD5.init)
hashMD5SHA1 = HashCtx (HashMD5SHA1 SHA1.init MD5.init)

{- key exchange methods encrypt and decrypt for each supported algorithm -}
generalizeRSAError :: Either RSA.Error a -> Either KxError a
generalizeRSAError (Left e)  = Left (RSAError e)
generalizeRSAError (Right x) = Right x

kxEncrypt :: CryptoRandomGen g => g -> PublicKey -> ByteString -> Either KxError (ByteString, g)
kxEncrypt g (PubRSA pk) b = generalizeRSAError $ RSA.encrypt g pk b

kxDecrypt :: PrivateKey -> ByteString -> Either KxError ByteString
kxDecrypt (PrivRSA pk) b  = generalizeRSAError $ RSA.decrypt pk b
