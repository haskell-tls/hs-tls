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
    , module Network.TLS.Crypto.IES
    , module Network.TLS.Crypto.Types

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
    , kxEncrypt
    , kxDecrypt
    , kxSign
    , kxVerify
    , KxError(..)
    ) where

import qualified Crypto.Hash as H
import qualified Data.ByteString as B
import qualified Data.ByteArray as B (convert)
import Data.ByteString (ByteString)
import Crypto.Random
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import Crypto.Number.Serialize (os2ip)

import Data.X509 (PrivKey(..), PubKey(..), PubKeyEC(..), SerializedPoint(..))
import Network.TLS.Crypto.DH
import Network.TLS.Crypto.IES
import Network.TLS.Crypto.Types

import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding (DER(..), BER(..))
import Data.List (find)

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
hashInit SHA224   = HashContext $ ContextSimple (H.hashInit :: H.Context H.SHA224)
hashInit SHA256   = HashContext $ ContextSimple (H.hashInit :: H.Context H.SHA256)
hashInit SHA384   = HashContext $ ContextSimple (H.hashInit :: H.Context H.SHA384)
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
hashFinal (HashContext (ContextSimple h)) = B.convert $ H.hashFinalize h
hashFinal (HashContextSSL sha1Ctx md5Ctx) =
    B.concat [B.convert (H.hashFinalize md5Ctx), B.convert (H.hashFinalize sha1Ctx)]

data Hash = MD5 | SHA1 | SHA224 | SHA256 | SHA384 | SHA512 | SHA1_MD5
    deriving (Show,Eq)

data HashContext =
      HashContext ContextSimple
    | HashContextSSL (H.Context H.SHA1) (H.Context H.MD5)

instance Show HashContext where
    show _ = "hash-context"

data ContextSimple = forall alg . H.HashAlgorithm alg => ContextSimple (H.Context alg)

type HashCtx = HashContext

hash :: Hash -> B.ByteString -> B.ByteString
hash MD5 b      = B.convert . (H.hash :: B.ByteString -> H.Digest H.MD5) $ b
hash SHA1 b     = B.convert . (H.hash :: B.ByteString -> H.Digest H.SHA1) $ b
hash SHA224 b   = B.convert . (H.hash :: B.ByteString -> H.Digest H.SHA224) $ b
hash SHA256 b   = B.convert . (H.hash :: B.ByteString -> H.Digest H.SHA256) $ b
hash SHA384 b   = B.convert . (H.hash :: B.ByteString -> H.Digest H.SHA384) $ b
hash SHA512 b   = B.convert . (H.hash :: B.ByteString -> H.Digest H.SHA512) $ b
hash SHA1_MD5 b =
    B.concat [B.convert (md5Hash b), B.convert (sha1Hash b)]
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
hashDigestSize SHA224 = 28
hashDigestSize SHA256 = 32
hashDigestSize SHA384 = 48
hashDigestSize SHA512 = 64
hashDigestSize SHA1_MD5 = 36

hashBlockSize :: Hash -> Int
hashBlockSize MD5    = 64
hashBlockSize SHA1   = 64
hashBlockSize SHA224 = 64
hashBlockSize SHA256 = 64
hashBlockSize SHA384 = 128
hashBlockSize SHA512 = 128
hashBlockSize SHA1_MD5 = 64

{- key exchange methods encrypt and decrypt for each supported algorithm -}

generalizeRSAError :: Either RSA.Error a -> Either KxError a
generalizeRSAError (Left e)  = Left (RSAError e)
generalizeRSAError (Right x) = Right x

kxEncrypt :: MonadRandom r => PublicKey -> ByteString -> r (Either KxError ByteString)
kxEncrypt (PubKeyRSA pk) b = generalizeRSAError `fmap` RSA.encrypt pk b
kxEncrypt _              _ = return (Left KxUnsupported)

kxDecrypt :: MonadRandom r => PrivateKey -> ByteString -> r (Either KxError ByteString)
kxDecrypt (PrivKeyRSA pk) b = generalizeRSAError `fmap` RSA.decryptSafer pk b
kxDecrypt _               _ = return (Left KxUnsupported)

-- Verify that the signature matches the given message, using the
-- public key.
--
kxVerify :: PublicKey -> Hash -> ByteString -> ByteString -> Bool
kxVerify (PubKeyRSA pk) alg msg sign = rsaVerifyHash alg pk msg sign
kxVerify (PubKeyDSA pk) _ msg signBS =
    case dsaToSignature signBS of
        Just sig -> DSA.verify H.SHA1 pk sig msg
        _        -> False
  where
        dsaToSignature :: ByteString -> Maybe DSA.Signature
        dsaToSignature b =
            case decodeASN1' BER b of
                Left _     -> Nothing
                Right asn1 ->
                    case asn1 of
                        Start Sequence:IntVal r:IntVal s:End Sequence:_ ->
                            Just $ DSA.Signature { DSA.sign_r = r, DSA.sign_s = s }
                        _ ->
                            Nothing
kxVerify (PubKeyEC key) alg msg sigBS = maybe False id $ do
    -- get the curve name and the public key data
    (curveName, pubBS) <- case key of
            PubKeyEC_Named curveName' pub -> Just (curveName',pub)
            PubKeyEC_Prime {}            ->
                case find matchPrimeCurve $ enumFrom $ toEnum 0 of
                    Nothing        -> Nothing
                    Just curveName' -> Just (curveName', pubkeyEC_pub key)
    -- decode the signature
    signature <- case decodeASN1' BER sigBS of
        Left _ -> Nothing
        Right [Start Sequence,IntVal r,IntVal s,End Sequence] -> Just $ ECDSA.Signature r s
        Right _ -> Nothing

    -- decode the public key related to the curve
    pubkey <- unserializePoint (ECC.getCurveByName curveName) pubBS

    verifyF <- case alg of
                    MD5    -> Just (ECDSA.verify H.MD5)
                    SHA1   -> Just (ECDSA.verify H.SHA1)
                    SHA224 -> Just (ECDSA.verify H.SHA224)
                    SHA256 -> Just (ECDSA.verify H.SHA256)
                    SHA384 -> Just (ECDSA.verify H.SHA384)
                    SHA512 -> Just (ECDSA.verify H.SHA512)
                    _      -> Nothing
    return $ verifyF pubkey signature msg
  where
        matchPrimeCurve c =
            case ECC.getCurveByName c of
                ECC.CurveFP (ECC.CurvePrime p cc) ->
                    ECC.ecc_a cc == pubkeyEC_a key     &&
                    ECC.ecc_b cc == pubkeyEC_b key     &&
                    ECC.ecc_n cc == pubkeyEC_order key &&
                    p            == pubkeyEC_prime key
                _                                 -> False

        unserializePoint curve (SerializedPoint bs) =
            case B.uncons bs of
                Nothing                -> Nothing
                Just (ptFormat, input) ->
                    case ptFormat of
                        4 -> if B.length input /= 2 * bytes
                                then Nothing
                                else
                                    let (x, y) = B.splitAt bytes input
                                        p      = ECC.Point (os2ip x) (os2ip y)
                                     in if ECC.isPointValid curve p
                                            then Just $ ECDSA.PublicKey curve p
                                            else Nothing
                        -- 2 and 3 for compressed format.
                        _ -> Nothing
          where bits  = ECC.curveSizeBits curve
                bytes = (bits + 7) `div` 8
kxVerify _              _         _   _    = False

-- Sign the given message using the private key.
--
kxSign :: MonadRandom r
       => PrivateKey
       -> Hash
       -> ByteString
       -> r (Either KxError ByteString)
kxSign (PrivKeyRSA pk) hashAlg msg =
    generalizeRSAError `fmap` rsaSignHash hashAlg pk msg
kxSign (PrivKeyDSA pk) _ msg = do
    sign <- DSA.sign pk H.SHA1 msg
    return (Right $ encodeASN1' DER $ dsaSequence sign)
  where dsaSequence sign = [Start Sequence,IntVal (DSA.sign_r sign),IntVal (DSA.sign_s sign),End Sequence]
--kxSign _ _ _ =
--    return (Left KxUnsupported)

rsaSignHash :: MonadRandom m => Hash -> RSA.PrivateKey -> ByteString -> m (Either RSA.Error ByteString)
rsaSignHash SHA1_MD5 pk msg = RSA.signSafer noHash pk msg
rsaSignHash MD5 pk msg      = RSA.signSafer (Just H.MD5) pk msg
rsaSignHash SHA1 pk msg     = RSA.signSafer (Just H.SHA1) pk msg
rsaSignHash SHA224 pk msg   = RSA.signSafer (Just H.SHA224) pk msg
rsaSignHash SHA256 pk msg   = RSA.signSafer (Just H.SHA256) pk msg
rsaSignHash SHA384 pk msg   = RSA.signSafer (Just H.SHA384) pk msg
rsaSignHash SHA512 pk msg   = RSA.signSafer (Just H.SHA512) pk msg

rsaVerifyHash :: Hash -> RSA.PublicKey -> ByteString -> ByteString -> Bool
rsaVerifyHash SHA1_MD5 = RSA.verify noHash
rsaVerifyHash MD5      = RSA.verify (Just H.MD5)
rsaVerifyHash SHA1     = RSA.verify (Just H.SHA1)
rsaVerifyHash SHA224   = RSA.verify (Just H.SHA224)
rsaVerifyHash SHA256   = RSA.verify (Just H.SHA256)
rsaVerifyHash SHA384   = RSA.verify (Just H.SHA384)
rsaVerifyHash SHA512   = RSA.verify (Just H.SHA512)

noHash :: Maybe H.MD5
noHash = Nothing
