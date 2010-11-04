module Network.TLS.Crypto
	( HashType(..)
	, HashCtx

	-- * incremental interface with algorithm type wrapping for genericity
	, initHash
	, updateHash
	, finalizeHash

	-- * single pass lazy bytestring interface for each algorithm
	, hashMD5
	, hashSHA1
	-- * incremental interface for each algorithm
	, initMD5
	, updateMD5
	, finalizeMD5
	, initSHA1
	, updateSHA1
	, finalizeSHA1

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

data HashCtx =
	  SHA1 !SHA1.Ctx
	| MD5 !MD5.Ctx

data KeyXchg =
	  KxRSA RSA.PublicKey RSA.PrivateKey
	deriving (Show)

instance Show HashCtx where
	show (SHA1 _) = "sha1"
	show (MD5 _) = "md5"

data HashType = HashTypeSHA1 | HashTypeMD5

{- MD5 -}

initMD5 :: MD5.Ctx
initMD5 = MD5.init

updateMD5 :: MD5.Ctx -> ByteString -> MD5.Ctx
updateMD5 = MD5.update

finalizeMD5 :: MD5.Ctx -> ByteString
finalizeMD5 = MD5.finalize

hashMD5 :: ByteString -> ByteString
hashMD5 = MD5.hash

{- SHA1 -}

initSHA1 :: SHA1.Ctx
initSHA1 = SHA1.init

updateSHA1 :: SHA1.Ctx -> ByteString -> SHA1.Ctx
updateSHA1 = SHA1.update

finalizeSHA1 :: SHA1.Ctx -> ByteString
finalizeSHA1 = SHA1.finalize

hashSHA1 :: ByteString -> ByteString
hashSHA1 = SHA1.hash

{- generic Hashing -}

initHash :: HashType -> HashCtx
initHash HashTypeSHA1 = SHA1 (initSHA1)
initHash HashTypeMD5  = MD5 (initMD5)

updateHash :: HashCtx -> B.ByteString -> HashCtx
updateHash (SHA1 ctx) = SHA1 . updateSHA1 ctx
updateHash (MD5 ctx)  = MD5 . updateMD5 ctx

finalizeHash :: HashCtx -> B.ByteString
finalizeHash (SHA1 ctx) = finalizeSHA1 ctx
finalizeHash (MD5 ctx)  = finalizeMD5 ctx

{- key exchange methods encrypt and decrypt for each supported algorithm -}
generalizeRSAError :: Either RSA.Error a -> Either KxError a
generalizeRSAError (Left e)  = Left (RSAError e)
generalizeRSAError (Right x) = Right x

kxEncrypt :: CryptoRandomGen g => g -> PublicKey -> ByteString -> Either KxError (ByteString, g)
kxEncrypt g (PubRSA pk) b = generalizeRSAError $ RSA.encrypt g pk b

kxDecrypt :: PrivateKey -> ByteString -> Either KxError ByteString
kxDecrypt (PrivRSA pk) b  = generalizeRSAError $ RSA.decrypt pk b
