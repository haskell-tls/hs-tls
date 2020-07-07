{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE RankNTypes #-}
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
    , SignatureParams(..)
    , isKeyExchangeSignatureKey
    , findKeyExchangeSignatureAlg
    , findFiniteFieldGroup
    , findEllipticCurveGroup
    , kxEncrypt
    , kxDecrypt
    , kxSign
    , kxVerify
    , kxCanUseRSApkcs1
    , kxCanUseRSApss
    , kxSupportedPrivKeyEC
    , KxError(..)
    , RSAEncoding(..)
    ) where

import qualified Crypto.Hash as H
import qualified Data.ByteString as B
import qualified Data.ByteArray as B (convert)
import Crypto.Error
import Crypto.Number.Basic (numBits)
import Crypto.Random
import qualified Crypto.ECC as ECDSA
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA_ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.ECDSA as ECDSA
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.RSA.PSS as PSS

import Data.X509 (PrivKey(..), PubKey(..), PrivKeyEC(..), PubKeyEC(..),
                  SerializedPoint(..))
import Data.X509.EC (ecPrivKeyCurveName, ecPubKeyCurveName, unserializePoint)
import Network.TLS.Crypto.DH
import Network.TLS.Crypto.IES
import Network.TLS.Crypto.Types
import Network.TLS.Imports

import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding (DER(..), BER(..))

import Data.Proxy

{-# DEPRECATED PublicKey "use PubKey" #-}
type PublicKey = PubKey
{-# DEPRECATED PrivateKey "use PrivKey" #-}
type PrivateKey = PrivKey

data KxError =
      RSAError RSA.Error
    | KxUnsupported
    deriving (Show)

isKeyExchangeSignatureKey :: KeyExchangeSignatureAlg -> PubKey -> Bool
isKeyExchangeSignatureKey = f
  where
    f KX_RSA   (PubKeyRSA     _)   = True
    f KX_DSS   (PubKeyDSA     _)   = True
    f KX_ECDSA (PubKeyEC      _)   = True
    f KX_ECDSA (PubKeyEd25519 _)   = True
    f KX_ECDSA (PubKeyEd448   _)   = True
    f _        _                   = False

findKeyExchangeSignatureAlg :: (PubKey, PrivKey) -> Maybe KeyExchangeSignatureAlg
findKeyExchangeSignatureAlg keyPair =
    case keyPair of
        (PubKeyRSA     _, PrivKeyRSA      _)  -> Just KX_RSA
        (PubKeyDSA     _, PrivKeyDSA      _)  -> Just KX_DSS
        (PubKeyEC      _, PrivKeyEC       _)  -> Just KX_ECDSA
        (PubKeyEd25519 _, PrivKeyEd25519  _)  -> Just KX_ECDSA
        (PubKeyEd448   _, PrivKeyEd448    _)  -> Just KX_ECDSA
        _                                     -> Nothing

findFiniteFieldGroup :: DH.Params -> Maybe Group
findFiniteFieldGroup params = lookup (pg params) table
  where
    pg (DH.Params p g _) = (p, g)

    table = [ (pg prms, grp) | grp <- availableFFGroups
                             , let Just prms = dhParamsForGroup grp
            ]

findEllipticCurveGroup :: PubKeyEC -> Maybe Group
findEllipticCurveGroup ecPub =
    case ecPubKeyCurveName ecPub of
        Just ECC.SEC_p256r1 -> Just P256
        Just ECC.SEC_p384r1 -> Just P384
        Just ECC.SEC_p521r1 -> Just P521
        _                   -> Nothing

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

-- | Digest size in bytes.
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
kxEncrypt (PubKeyRSA pk) b = generalizeRSAError <$> RSA.encrypt pk b
kxEncrypt _              _ = return (Left KxUnsupported)

kxDecrypt :: MonadRandom r => PrivateKey -> ByteString -> r (Either KxError ByteString)
kxDecrypt (PrivKeyRSA pk) b = generalizeRSAError <$> RSA.decryptSafer pk b
kxDecrypt _               _ = return (Left KxUnsupported)

data RSAEncoding = RSApkcs1 | RSApss deriving (Show,Eq)

-- | Test the RSASSA-PKCS1 length condition described in RFC 8017 section 9.2,
-- i.e. @emLen >= tLen + 11@.  Lengths are in bytes.
kxCanUseRSApkcs1 :: RSA.PublicKey -> Hash -> Bool
kxCanUseRSApkcs1 pk h = RSA.public_size pk >= tLen + 11
  where
    tLen = prefixSize h + hashDigestSize h

    prefixSize MD5    = 18
    prefixSize SHA1   = 15
    prefixSize SHA224 = 19
    prefixSize SHA256 = 19
    prefixSize SHA384 = 19
    prefixSize SHA512 = 19
    prefixSize _      = error (show h ++ " is not supported for RSASSA-PKCS1")

-- | Test the RSASSA-PSS length condition described in RFC 8017 section 9.1.1,
-- i.e. @emBits >= 8hLen + 8sLen + 9@.  Lengths are in bits.
kxCanUseRSApss :: RSA.PublicKey -> Hash -> Bool
kxCanUseRSApss pk h = numBits (RSA.public_n pk) >= 16 * hashDigestSize h + 10

-- Signature algorithm and associated parameters.
--
-- FIXME add RSAPSSParams
data SignatureParams =
      RSAParams      Hash RSAEncoding
    | DSSParams
    | ECDSAParams    Hash
    | Ed25519Params
    | Ed448Params
    deriving (Show,Eq)

-- Verify that the signature matches the given message, using the
-- public key.
--

kxVerify :: PublicKey -> SignatureParams -> ByteString -> ByteString -> Bool
kxVerify (PubKeyRSA pk) (RSAParams alg RSApkcs1) msg sign   = rsaVerifyHash alg pk msg sign
kxVerify (PubKeyRSA pk) (RSAParams alg RSApss)   msg sign   = rsapssVerifyHash alg pk msg sign
kxVerify (PubKeyDSA pk) DSSParams                msg signBS =

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
                            Just DSA.Signature { DSA.sign_r = r, DSA.sign_s = s }
                        _ ->
                            Nothing
kxVerify (PubKeyEC key) (ECDSAParams alg) msg sigBS =
    fromMaybe False $ join $
        withPubKeyEC key verifyProxy verifyClassic Nothing
  where
    decodeSignatureASN1 buildRS =
        case decodeASN1' BER sigBS of
            Left _  -> Nothing
            Right [Start Sequence,IntVal r,IntVal s,End Sequence] ->
                Just (buildRS r s)
            Right _ -> Nothing
    verifyProxy prx pubkey = do
        rs <- decodeSignatureASN1 (,)
        signature <- maybeCryptoError $ ECDSA.signatureFromIntegers prx rs
        verifyF <- withAlg (ECDSA.verify prx)
        return $ verifyF pubkey signature msg
    verifyClassic pubkey = do
        signature <- decodeSignatureASN1 ECDSA_ECC.Signature
        verifyF <- withAlg ECDSA_ECC.verify
        return $ verifyF pubkey signature msg
    withAlg :: (forall hash . H.HashAlgorithm hash => hash -> a) -> Maybe a
    withAlg f = case alg of
                    MD5    -> Just (f H.MD5)
                    SHA1   -> Just (f H.SHA1)
                    SHA224 -> Just (f H.SHA224)
                    SHA256 -> Just (f H.SHA256)
                    SHA384 -> Just (f H.SHA384)
                    SHA512 -> Just (f H.SHA512)
                    _      -> Nothing
kxVerify (PubKeyEd25519 key) Ed25519Params msg sigBS =
    case Ed25519.signature sigBS of
        CryptoPassed sig -> Ed25519.verify key msg sig
        _                -> False
kxVerify (PubKeyEd448 key) Ed448Params msg sigBS =
    case Ed448.signature sigBS of
        CryptoPassed sig -> Ed448.verify key msg sig
        _                -> False
kxVerify _              _         _   _    = False

-- Sign the given message using the private key.
--
kxSign :: MonadRandom r
       => PrivateKey
       -> PublicKey
       -> SignatureParams
       -> ByteString
       -> r (Either KxError ByteString)
kxSign (PrivKeyRSA pk) (PubKeyRSA _) (RSAParams hashAlg RSApkcs1) msg =
    generalizeRSAError <$> rsaSignHash hashAlg pk msg
kxSign (PrivKeyRSA pk) (PubKeyRSA _) (RSAParams hashAlg RSApss) msg =
    generalizeRSAError <$> rsapssSignHash hashAlg pk msg
kxSign (PrivKeyDSA pk) (PubKeyDSA _) DSSParams msg = do
    sign <- DSA.sign pk H.SHA1 msg
    return (Right $ encodeASN1' DER $ dsaSequence sign)
  where dsaSequence sign = [Start Sequence,IntVal (DSA.sign_r sign),IntVal (DSA.sign_s sign),End Sequence]
kxSign (PrivKeyEC pk) (PubKeyEC _) (ECDSAParams hashAlg) msg =
    case withPrivKeyEC pk doSign (const unsupported) unsupported of
        Nothing  -> unsupported
        Just run -> fmap encode <$> run
  where encode (r, s) = encodeASN1' DER
            [ Start Sequence, IntVal r, IntVal s, End Sequence ]
        doSign prx privkey = do
            msig <- ecdsaSignHash prx hashAlg privkey msg
            return $ case msig of
                         Nothing   -> Left KxUnsupported
                         Just sign -> Right (ECDSA.signatureToIntegers prx sign)
        unsupported = return $ Left KxUnsupported
kxSign (PrivKeyEd25519 pk) (PubKeyEd25519 pub) Ed25519Params msg =
    return $ Right $ B.convert $ Ed25519.sign pk pub msg
kxSign (PrivKeyEd448 pk) (PubKeyEd448 pub) Ed448Params msg =
    return $ Right $ B.convert $ Ed448.sign pk pub msg
kxSign _ _ _ _ =
    return (Left KxUnsupported)

rsaSignHash :: MonadRandom m => Hash -> RSA.PrivateKey -> ByteString -> m (Either RSA.Error ByteString)
rsaSignHash SHA1_MD5 pk msg = RSA.signSafer noHash pk msg
rsaSignHash MD5 pk msg      = RSA.signSafer (Just H.MD5) pk msg
rsaSignHash SHA1 pk msg     = RSA.signSafer (Just H.SHA1) pk msg
rsaSignHash SHA224 pk msg   = RSA.signSafer (Just H.SHA224) pk msg
rsaSignHash SHA256 pk msg   = RSA.signSafer (Just H.SHA256) pk msg
rsaSignHash SHA384 pk msg   = RSA.signSafer (Just H.SHA384) pk msg
rsaSignHash SHA512 pk msg   = RSA.signSafer (Just H.SHA512) pk msg

rsapssSignHash :: MonadRandom m => Hash -> RSA.PrivateKey -> ByteString -> m (Either RSA.Error ByteString)
rsapssSignHash SHA256 pk msg = PSS.signSafer (PSS.defaultPSSParams H.SHA256) pk msg
rsapssSignHash SHA384 pk msg = PSS.signSafer (PSS.defaultPSSParams H.SHA384) pk msg
rsapssSignHash SHA512 pk msg = PSS.signSafer (PSS.defaultPSSParams H.SHA512) pk msg
rsapssSignHash _ _ _         = error "rsapssSignHash: unsupported hash"

rsaVerifyHash :: Hash -> RSA.PublicKey -> ByteString -> ByteString -> Bool
rsaVerifyHash SHA1_MD5 = RSA.verify noHash
rsaVerifyHash MD5      = RSA.verify (Just H.MD5)
rsaVerifyHash SHA1     = RSA.verify (Just H.SHA1)
rsaVerifyHash SHA224   = RSA.verify (Just H.SHA224)
rsaVerifyHash SHA256   = RSA.verify (Just H.SHA256)
rsaVerifyHash SHA384   = RSA.verify (Just H.SHA384)
rsaVerifyHash SHA512   = RSA.verify (Just H.SHA512)

rsapssVerifyHash :: Hash -> RSA.PublicKey -> ByteString -> ByteString -> Bool
rsapssVerifyHash SHA256 = PSS.verify (PSS.defaultPSSParams H.SHA256)
rsapssVerifyHash SHA384 = PSS.verify (PSS.defaultPSSParams H.SHA384)
rsapssVerifyHash SHA512 = PSS.verify (PSS.defaultPSSParams H.SHA512)
rsapssVerifyHash _      = error "rsapssVerifyHash: unsupported hash"

noHash :: Maybe H.MD5
noHash = Nothing

ecdsaSignHash :: (MonadRandom m, ECDSA.EllipticCurveECDSA curve)
              => proxy curve -> Hash -> ECDSA.Scalar curve -> ByteString -> m (Maybe (ECDSA.Signature curve))
ecdsaSignHash prx SHA1   pk msg   = Just <$> ECDSA.sign prx pk H.SHA1   msg
ecdsaSignHash prx SHA224 pk msg   = Just <$> ECDSA.sign prx pk H.SHA224 msg
ecdsaSignHash prx SHA256 pk msg   = Just <$> ECDSA.sign prx pk H.SHA256 msg
ecdsaSignHash prx SHA384 pk msg   = Just <$> ECDSA.sign prx pk H.SHA384 msg
ecdsaSignHash prx SHA512 pk msg   = Just <$> ECDSA.sign prx pk H.SHA512 msg
ecdsaSignHash _   _      _  _     = return Nothing

-- Currently we generate ECDSA signatures in constant time for P256 only.
kxSupportedPrivKeyEC :: PrivKeyEC -> Bool
kxSupportedPrivKeyEC privkey =
    case ecPrivKeyCurveName privkey of
        Just ECC.SEC_p256r1 -> True
        _                   -> False

-- Perform a public-key operation with a parameterized ECC implementation when
-- available, otherwise fallback to the classic ECC implementation.
withPubKeyEC :: PubKeyEC
             -> (forall curve . ECDSA.EllipticCurveECDSA curve => Proxy curve -> ECDSA.PublicKey curve -> a)
             -> (ECDSA_ECC.PublicKey -> a)
             -> a
             -> Maybe a
withPubKeyEC pubkey withProxy withClassic whenUnknown =
    case ecPubKeyCurveName pubkey of
        Nothing             -> Just whenUnknown
        Just ECC.SEC_p256r1 ->
            maybeCryptoError $ withProxy p256 <$> ECDSA.decodePublic p256 bs
        Just curveName      ->
            let curve = ECC.getCurveByName curveName
                pub   = unserializePoint curve pt
             in withClassic . ECDSA_ECC.PublicKey curve <$> pub
  where pt@(SerializedPoint bs) = pubkeyEC_pub pubkey

-- Perform a private-key operation with a parameterized ECC implementation when
-- available.  Calls for an unsupported curve can be prevented with
-- kxSupportedEcPrivKey.
withPrivKeyEC :: PrivKeyEC
              -> (forall curve . ECDSA.EllipticCurveECDSA curve => Proxy curve -> ECDSA.PrivateKey curve -> a)
              -> (ECC.CurveName -> a)
              -> a
              -> Maybe a
withPrivKeyEC privkey withProxy withUnsupported whenUnknown =
    case ecPrivKeyCurveName privkey of
        Nothing             -> Just whenUnknown
        Just ECC.SEC_p256r1 ->
            -- Private key should rather be stored as bytearray and converted
            -- using ECDSA.decodePrivate, unfortunately the data type chosen in
            -- x509 was Integer.
            maybeCryptoError $ withProxy p256 <$> ECDSA.scalarFromInteger p256 d
        Just curveName      -> Just $ withUnsupported curveName
  where d = privkeyEC_priv privkey

p256 :: Proxy ECDSA.Curve_P256R1
p256 = Proxy
