{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE DeriveDataTypeable #-}
-- |
-- Module      : Network.TLS.Struct
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Struct module contains all definitions and values of the TLS protocol
--
{-# LANGUAGE CPP #-}
module Network.TLS.Struct
    ( Version(..)
    , ConnectionEnd(..)
    , CipherType(..)
    , CipherData(..)
    , ExtensionID
    , ExtensionRaw(..)
    , CertificateType(..)
    , lastSupportedCertificateType
    , HashAlgorithm(..)
    , SignatureAlgorithm(..)
    , HashAndSignatureAlgorithm
    , DigitallySigned(..)
    , Signature
    , ProtocolType(..)
    , TLSError(..)
    , TLSException(..)
    , DistinguishedName
    , BigNum(..)
    , bigNumToInteger
    , bigNumFromInteger
    , ServerDHParams(..)
    , serverDHParamsToParams
    , serverDHParamsToPublic
    , serverDHParamsFrom
    , ServerECDHParams(..)
    , ServerRSAParams(..)
    , ServerKeyXchgAlgorithmData(..)
    , ClientKeyXchgAlgorithmData(..)
    , Packet(..)
    , Header(..)
    , ServerRandom(..)
    , ClientRandom(..)
    , FinishedData
    , SessionID
    , Session(..)
    , SessionData(..)
    , AlertLevel(..)
    , AlertDescription(..)
    , HandshakeType(..)
    , Handshake(..)
    , numericalVer
    , verOfNum
    , TypeValuable, valOfType, valToType
    , EnumSafe8(..)
    , EnumSafe16(..)
    , packetType
    , typeOfHandshake
    ) where

import Data.X509 (CertificateChain, DistinguishedName)
import Data.Typeable
import Control.Exception (Exception(..))
import Network.TLS.Types
import Network.TLS.Crypto
import Network.TLS.Util.Serialization
import Network.TLS.Imports
#if MIN_VERSION_mtl(2,2,1)
#else
import Control.Monad.Error
#endif

data ConnectionEnd = ConnectionServer | ConnectionClient
data CipherType = CipherStream | CipherBlock | CipherAEAD

data CipherData = CipherData
    { cipherDataContent :: ByteString
    , cipherDataMAC     :: Maybe ByteString
    , cipherDataPadding :: Maybe ByteString
    } deriving (Show,Eq)

-- | Some of the IANA registered code points for 'CertificateType' are not
-- currently supported by the library.  Nor should they be, they're are either
-- unwise, obsolete or both.  There's no point in conveying these to the user
-- in the client certificate request callback.  The request callback will be
-- filtered to exclude unsupported values.  If the user cannot find a certificate
-- for a supported code point, we'll go ahead without a client certificate and
-- hope for the best, unless the user's callback decides to throw an exception.
--
data CertificateType =
      CertificateType_RSA_Sign         -- ^ TLS10 and up, RFC5246
    | CertificateType_DSS_Sign         -- ^ TLS10 and up, RFC5246
    | CertificateType_ECDSA_Sign       -- ^ TLS10 and up, RFC8422
    | CertificateType_Ed25519_Sign     -- ^ TLS13 and up, synthetic
    | CertificateType_Ed448_Sign       -- ^ TLS13 and up, synthetic
    -- | None of the below will ever be presented to the callback.  Any future
    -- public key algorithms valid for client certificates go above this line.
    | CertificateType_RSA_Fixed_DH     -- Obsolete, unsupported
    | CertificateType_DSS_Fixed_DH     -- Obsolete, unsupported
    | CertificateType_RSA_Ephemeral_DH -- Obsolete, unsupported
    | CertificateType_DSS_Ephemeral_DH -- Obsolete, unsupported
    | CertificateType_fortezza_dms     -- Obsolete, unsupported
    | CertificateType_RSA_Fixed_ECDH   -- Obsolete, unsupported
    | CertificateType_ECDSA_Fixed_ECDH -- Obsolete, unsupported
    | CertificateType_Unknown Word8    -- Obsolete, unsupported
    deriving (Eq, Ord, Show)

-- | Last supported certificate type, no 'CertificateType that
-- compares greater than this one (based on the 'Ord' instance,
-- not on the wire code point) will be reported to the application
-- via the client certificate request callback.
--
lastSupportedCertificateType :: CertificateType
lastSupportedCertificateType = CertificateType_DSS_Sign


data HashAlgorithm =
      HashNone
    | HashMD5
    | HashSHA1
    | HashSHA224
    | HashSHA256
    | HashSHA384
    | HashSHA512
    | HashIntrinsic
    | HashOther Word8
    deriving (Show,Eq)

data SignatureAlgorithm =
      SignatureAnonymous
    | SignatureRSA
    | SignatureDSS
    | SignatureECDSA
    | SignatureRSApssRSAeSHA256
    | SignatureRSApssRSAeSHA384
    | SignatureRSApssRSAeSHA512
    | SignatureEd25519
    | SignatureEd448
    | SignatureRSApsspssSHA256
    | SignatureRSApsspssSHA384
    | SignatureRSApsspssSHA512
    | SignatureOther Word8
    deriving (Show,Eq)

type HashAndSignatureAlgorithm = (HashAlgorithm, SignatureAlgorithm)

------------------------------------------------------------

type Signature = ByteString

data DigitallySigned = DigitallySigned (Maybe HashAndSignatureAlgorithm) Signature
    deriving (Show,Eq)

data ProtocolType =
      ProtocolType_ChangeCipherSpec
    | ProtocolType_Alert
    | ProtocolType_Handshake
    | ProtocolType_AppData
    | ProtocolType_DeprecatedHandshake
    deriving (Eq, Show)

-- | TLSError that might be returned through the TLS stack
data TLSError =
      Error_Misc String        -- ^ mainly for instance of Error
    | Error_Protocol (String, Bool, AlertDescription)
    | Error_Certificate String
    | Error_HandshakePolicy String -- ^ handshake policy failed.
    | Error_EOF
    | Error_Packet String
    | Error_Packet_unexpected String String
    | Error_Packet_Parsing String
    deriving (Eq, Show, Typeable)

#if MIN_VERSION_mtl(2,2,1)
#else
instance Error TLSError where
    noMsg  = Error_Misc ""
    strMsg = Error_Misc
#endif

instance Exception TLSError

-- | TLS Exceptions related to bad user usage or
-- asynchronous errors
data TLSException =
      Terminated Bool String TLSError -- ^ Early termination exception with the reason
                                      --   and the error associated
    | HandshakeFailed TLSError        -- ^ Handshake failed for the reason attached
    | ConnectionNotEstablished        -- ^ Usage error when the connection has not been established
                                      --   and the user is trying to send or receive data
    deriving (Show,Eq,Typeable)

instance Exception TLSException

data Packet =
      Handshake [Handshake]
    | Alert [(AlertLevel, AlertDescription)]
    | ChangeCipherSpec
    | AppData ByteString
    deriving (Show,Eq)

data Header = Header ProtocolType Version Word16 deriving (Show,Eq)

newtype ServerRandom = ServerRandom { unServerRandom :: ByteString } deriving (Show, Eq)
newtype ClientRandom = ClientRandom { unClientRandom :: ByteString } deriving (Show, Eq)
newtype Session = Session (Maybe SessionID) deriving (Show, Eq)

type FinishedData = ByteString
type ExtensionID  = Word16

data ExtensionRaw = ExtensionRaw ExtensionID ByteString
    deriving (Eq)

instance Show ExtensionRaw where
    show (ExtensionRaw eid bs) = "ExtensionRaw " ++ show eid ++ " " ++ showBytesHex bs ++ ""

data AlertLevel =
      AlertLevel_Warning
    | AlertLevel_Fatal
    deriving (Show,Eq)

data AlertDescription =
      CloseNotify
    | UnexpectedMessage
    | BadRecordMac
    | DecryptionFailed       -- ^ deprecated alert, should never be sent by compliant implementation
    | RecordOverflow
    | DecompressionFailure
    | HandshakeFailure
    | BadCertificate
    | UnsupportedCertificate
    | CertificateRevoked
    | CertificateExpired
    | CertificateUnknown
    | IllegalParameter
    | UnknownCa
    | AccessDenied
    | DecodeError
    | DecryptError
    | ExportRestriction
    | ProtocolVersion
    | InsufficientSecurity
    | InternalError
    | InappropriateFallback -- RFC7507
    | UserCanceled
    | NoRenegotiation
    | MissingExtension
    | UnsupportedExtension
    | CertificateUnobtainable
    | UnrecognizedName
    | BadCertificateStatusResponse
    | BadCertificateHashValue
    | UnknownPskIdentity
    | CertificateRequired
    | NoApplicationProtocol -- RFC7301
    deriving (Show,Eq)

data HandshakeType =
      HandshakeType_HelloRequest
    | HandshakeType_ClientHello
    | HandshakeType_ServerHello
    | HandshakeType_Certificate
    | HandshakeType_ServerKeyXchg
    | HandshakeType_CertRequest
    | HandshakeType_ServerHelloDone
    | HandshakeType_CertVerify
    | HandshakeType_ClientKeyXchg
    | HandshakeType_Finished
    deriving (Show,Eq)

newtype BigNum = BigNum ByteString
    deriving (Show,Eq)

bigNumToInteger :: BigNum -> Integer
bigNumToInteger (BigNum b) = os2ip b

bigNumFromInteger :: Integer -> BigNum
bigNumFromInteger i = BigNum $ i2osp i

data ServerDHParams = ServerDHParams
    { serverDHParams_p :: BigNum
    , serverDHParams_g :: BigNum
    , serverDHParams_y :: BigNum
    } deriving (Show,Eq)

serverDHParamsFrom :: DHParams -> DHPublic -> ServerDHParams
serverDHParamsFrom params dhPub =
    ServerDHParams (bigNumFromInteger $ dhParamsGetP params)
                   (bigNumFromInteger $ dhParamsGetG params)
                   (bigNumFromInteger $ dhUnwrapPublic dhPub)

serverDHParamsToParams :: ServerDHParams -> DHParams
serverDHParamsToParams serverParams =
    dhParams (bigNumToInteger $ serverDHParams_p serverParams)
             (bigNumToInteger $ serverDHParams_g serverParams)

serverDHParamsToPublic :: ServerDHParams -> DHPublic
serverDHParamsToPublic serverParams =
    dhPublic (bigNumToInteger $ serverDHParams_y serverParams)

data ServerECDHParams = ServerECDHParams Group GroupPublic
    deriving (Show,Eq)

data ServerRSAParams = ServerRSAParams
    { rsa_modulus  :: Integer
    , rsa_exponent :: Integer
    } deriving (Show,Eq)

data ServerKeyXchgAlgorithmData =
      SKX_DH_Anon ServerDHParams
    | SKX_DHE_DSS ServerDHParams DigitallySigned
    | SKX_DHE_RSA ServerDHParams DigitallySigned
    | SKX_ECDHE_RSA ServerECDHParams DigitallySigned
    | SKX_ECDHE_ECDSA ServerECDHParams DigitallySigned
    | SKX_RSA (Maybe ServerRSAParams)
    | SKX_DH_DSS (Maybe ServerRSAParams)
    | SKX_DH_RSA (Maybe ServerRSAParams)
    | SKX_Unparsed ByteString -- if we parse the server key xchg before knowing the actual cipher, we end up with this structure.
    | SKX_Unknown ByteString
    deriving (Show,Eq)

data ClientKeyXchgAlgorithmData =
      CKX_RSA ByteString
    | CKX_DH DHPublic
    | CKX_ECDH ByteString
    deriving (Show,Eq)

type DeprecatedRecord = ByteString

data Handshake =
      ClientHello !Version !ClientRandom !Session ![CipherID] ![CompressionID] [ExtensionRaw] (Maybe DeprecatedRecord)
    | ServerHello !Version !ServerRandom !Session !CipherID !CompressionID [ExtensionRaw]
    | Certificates CertificateChain
    | HelloRequest
    | ServerHelloDone
    | ClientKeyXchg ClientKeyXchgAlgorithmData
    | ServerKeyXchg ServerKeyXchgAlgorithmData
    | CertRequest [CertificateType] (Maybe [HashAndSignatureAlgorithm]) [DistinguishedName]
    | CertVerify DigitallySigned
    | Finished FinishedData
    deriving (Show,Eq)

packetType :: Packet -> ProtocolType
packetType (Handshake _)    = ProtocolType_Handshake
packetType (Alert _)        = ProtocolType_Alert
packetType ChangeCipherSpec = ProtocolType_ChangeCipherSpec
packetType (AppData _)      = ProtocolType_AppData

typeOfHandshake :: Handshake -> HandshakeType
typeOfHandshake ClientHello{}             = HandshakeType_ClientHello
typeOfHandshake ServerHello{}             = HandshakeType_ServerHello
typeOfHandshake Certificates{}            = HandshakeType_Certificate
typeOfHandshake HelloRequest              = HandshakeType_HelloRequest
typeOfHandshake ServerHelloDone           = HandshakeType_ServerHelloDone
typeOfHandshake ClientKeyXchg{}           = HandshakeType_ClientKeyXchg
typeOfHandshake ServerKeyXchg{}           = HandshakeType_ServerKeyXchg
typeOfHandshake CertRequest{}             = HandshakeType_CertRequest
typeOfHandshake CertVerify{}              = HandshakeType_CertVerify
typeOfHandshake Finished{}                = HandshakeType_Finished

numericalVer :: Version -> (Word8, Word8)
numericalVer SSL2  = (2, 0)
numericalVer SSL3  = (3, 0)
numericalVer TLS10 = (3, 1)
numericalVer TLS11 = (3, 2)
numericalVer TLS12 = (3, 3)
numericalVer TLS13 = (3, 4)

verOfNum :: (Word8, Word8) -> Maybe Version
verOfNum (2, 0) = Just SSL2
verOfNum (3, 0) = Just SSL3
verOfNum (3, 1) = Just TLS10
verOfNum (3, 2) = Just TLS11
verOfNum (3, 3) = Just TLS12
verOfNum (3, 4) = Just TLS13
verOfNum _      = Nothing

class TypeValuable a where
    valOfType :: a -> Word8
    valToType :: Word8 -> Maybe a

-- a better name for TypeValuable
class EnumSafe8 a where
    fromEnumSafe8 :: a -> Word8
    toEnumSafe8   :: Word8 -> Maybe a

class EnumSafe16 a where
    fromEnumSafe16 :: a -> Word16
    toEnumSafe16   :: Word16 -> Maybe a

instance TypeValuable ConnectionEnd where
    valOfType ConnectionServer = 0
    valOfType ConnectionClient = 1

    valToType 0 = Just ConnectionServer
    valToType 1 = Just ConnectionClient
    valToType _ = Nothing

instance TypeValuable CipherType where
    valOfType CipherStream = 0
    valOfType CipherBlock  = 1
    valOfType CipherAEAD   = 2

    valToType 0 = Just CipherStream
    valToType 1 = Just CipherBlock
    valToType 2 = Just CipherAEAD
    valToType _ = Nothing

instance TypeValuable ProtocolType where
    valOfType ProtocolType_ChangeCipherSpec    = 20
    valOfType ProtocolType_Alert               = 21
    valOfType ProtocolType_Handshake           = 22
    valOfType ProtocolType_AppData             = 23
    valOfType ProtocolType_DeprecatedHandshake = 128 -- unused

    valToType 20 = Just ProtocolType_ChangeCipherSpec
    valToType 21 = Just ProtocolType_Alert
    valToType 22 = Just ProtocolType_Handshake
    valToType 23 = Just ProtocolType_AppData
    valToType _  = Nothing

instance TypeValuable HandshakeType where
    valOfType HandshakeType_HelloRequest    = 0
    valOfType HandshakeType_ClientHello     = 1
    valOfType HandshakeType_ServerHello     = 2
    valOfType HandshakeType_Certificate     = 11
    valOfType HandshakeType_ServerKeyXchg   = 12
    valOfType HandshakeType_CertRequest     = 13
    valOfType HandshakeType_ServerHelloDone = 14
    valOfType HandshakeType_CertVerify      = 15
    valOfType HandshakeType_ClientKeyXchg   = 16
    valOfType HandshakeType_Finished        = 20

    valToType 0  = Just HandshakeType_HelloRequest
    valToType 1  = Just HandshakeType_ClientHello
    valToType 2  = Just HandshakeType_ServerHello
    valToType 11 = Just HandshakeType_Certificate
    valToType 12 = Just HandshakeType_ServerKeyXchg
    valToType 13 = Just HandshakeType_CertRequest
    valToType 14 = Just HandshakeType_ServerHelloDone
    valToType 15 = Just HandshakeType_CertVerify
    valToType 16 = Just HandshakeType_ClientKeyXchg
    valToType 20 = Just HandshakeType_Finished
    valToType _  = Nothing

instance TypeValuable AlertLevel where
    valOfType AlertLevel_Warning = 1
    valOfType AlertLevel_Fatal   = 2

    valToType 1 = Just AlertLevel_Warning
    valToType 2 = Just AlertLevel_Fatal
    valToType _ = Nothing

instance TypeValuable AlertDescription where
    valOfType CloseNotify            = 0
    valOfType UnexpectedMessage      = 10
    valOfType BadRecordMac           = 20
    valOfType DecryptionFailed       = 21
    valOfType RecordOverflow         = 22
    valOfType DecompressionFailure   = 30
    valOfType HandshakeFailure       = 40
    valOfType BadCertificate         = 42
    valOfType UnsupportedCertificate = 43
    valOfType CertificateRevoked     = 44
    valOfType CertificateExpired     = 45
    valOfType CertificateUnknown     = 46
    valOfType IllegalParameter       = 47
    valOfType UnknownCa              = 48
    valOfType AccessDenied           = 49
    valOfType DecodeError            = 50
    valOfType DecryptError           = 51
    valOfType ExportRestriction      = 60
    valOfType ProtocolVersion        = 70
    valOfType InsufficientSecurity   = 71
    valOfType InternalError          = 80
    valOfType InappropriateFallback  = 86
    valOfType UserCanceled           = 90
    valOfType NoRenegotiation        = 100
    valOfType MissingExtension       = 109
    valOfType UnsupportedExtension   = 110
    valOfType CertificateUnobtainable = 111
    valOfType UnrecognizedName        = 112
    valOfType BadCertificateStatusResponse = 113
    valOfType BadCertificateHashValue = 114
    valOfType UnknownPskIdentity      = 115
    valOfType CertificateRequired     = 116
    valOfType NoApplicationProtocol   = 120

    valToType 0   = Just CloseNotify
    valToType 10  = Just UnexpectedMessage
    valToType 20  = Just BadRecordMac
    valToType 21  = Just DecryptionFailed
    valToType 22  = Just RecordOverflow
    valToType 30  = Just DecompressionFailure
    valToType 40  = Just HandshakeFailure
    valToType 42  = Just BadCertificate
    valToType 43  = Just UnsupportedCertificate
    valToType 44  = Just CertificateRevoked
    valToType 45  = Just CertificateExpired
    valToType 46  = Just CertificateUnknown
    valToType 47  = Just IllegalParameter
    valToType 48  = Just UnknownCa
    valToType 49  = Just AccessDenied
    valToType 50  = Just DecodeError
    valToType 51  = Just DecryptError
    valToType 60  = Just ExportRestriction
    valToType 70  = Just ProtocolVersion
    valToType 71  = Just InsufficientSecurity
    valToType 80  = Just InternalError
    valToType 86  = Just InappropriateFallback
    valToType 90  = Just UserCanceled
    valToType 100 = Just NoRenegotiation
    valToType 109 = Just MissingExtension
    valToType 110 = Just UnsupportedExtension
    valToType 111 = Just CertificateUnobtainable
    valToType 112 = Just UnrecognizedName
    valToType 113 = Just BadCertificateStatusResponse
    valToType 114 = Just BadCertificateHashValue
    valToType 115 = Just UnknownPskIdentity
    valToType 116 = Just CertificateRequired
    valToType 120 = Just NoApplicationProtocol
    valToType _   = Nothing

instance TypeValuable CertificateType where
    valOfType CertificateType_RSA_Sign         = 1
    valOfType CertificateType_ECDSA_Sign       = 64
    valOfType CertificateType_DSS_Sign         = 2
    valOfType CertificateType_RSA_Fixed_DH     = 3
    valOfType CertificateType_DSS_Fixed_DH     = 4
    valOfType CertificateType_RSA_Ephemeral_DH = 5
    valOfType CertificateType_DSS_Ephemeral_DH = 6
    valOfType CertificateType_fortezza_dms     = 20
    valOfType CertificateType_RSA_Fixed_ECDH   = 65
    valOfType CertificateType_ECDSA_Fixed_ECDH = 66
    valOfType (CertificateType_Unknown i)      = i
    -- | There are no code points that map to the below synthetic types, these
    -- are inferred indirectly from the @signature_algorithms@ extension of the
    -- TLS 1.3 @CertificateRequest@ message.  the value assignments are there
    -- only to avoid partial function warnings.
    valOfType CertificateType_Ed25519_Sign     = 0
    valOfType CertificateType_Ed448_Sign       = 0

    valToType 1  = Just CertificateType_RSA_Sign
    valToType 2  = Just CertificateType_DSS_Sign
    valToType 3  = Just CertificateType_RSA_Fixed_DH
    valToType 4  = Just CertificateType_DSS_Fixed_DH
    valToType 5  = Just CertificateType_RSA_Ephemeral_DH
    valToType 6  = Just CertificateType_DSS_Ephemeral_DH
    valToType 20 = Just CertificateType_fortezza_dms
    valToType 64 = Just CertificateType_ECDSA_Sign
    valToType 65 = Just CertificateType_RSA_Fixed_ECDH
    valToType 66 = Just CertificateType_ECDSA_Fixed_ECDH
    valToType i  = Just (CertificateType_Unknown i)
    -- | There are no code points that map to the below synthetic types, these
    -- are inferred indirectly from the @signature_algorithms@ extension of the
    -- TLS 1.3 @CertificateRequest@ message.
    -- @
    -- CertificateType_Ed25519_Sign
    -- CertificateType_Ed448_Sign
    -- @

instance TypeValuable HashAlgorithm where
    valOfType HashNone      = 0
    valOfType HashMD5       = 1
    valOfType HashSHA1      = 2
    valOfType HashSHA224    = 3
    valOfType HashSHA256    = 4
    valOfType HashSHA384    = 5
    valOfType HashSHA512    = 6
    valOfType HashIntrinsic = 8
    valOfType (HashOther i) = i

    valToType 0 = Just HashNone
    valToType 1 = Just HashMD5
    valToType 2 = Just HashSHA1
    valToType 3 = Just HashSHA224
    valToType 4 = Just HashSHA256
    valToType 5 = Just HashSHA384
    valToType 6 = Just HashSHA512
    valToType 8 = Just HashIntrinsic
    valToType i = Just (HashOther i)

instance TypeValuable SignatureAlgorithm where
    valOfType SignatureAnonymous        =  0
    valOfType SignatureRSA              =  1
    valOfType SignatureDSS              =  2
    valOfType SignatureECDSA            =  3
    valOfType SignatureRSApssRSAeSHA256 =  4
    valOfType SignatureRSApssRSAeSHA384 =  5
    valOfType SignatureRSApssRSAeSHA512 =  6
    valOfType SignatureEd25519          =  7
    valOfType SignatureEd448            =  8
    valOfType SignatureRSApsspssSHA256  =  9
    valOfType SignatureRSApsspssSHA384  = 10
    valOfType SignatureRSApsspssSHA512  = 11
    valOfType (SignatureOther i)        =  i

    valToType  0 = Just SignatureAnonymous
    valToType  1 = Just SignatureRSA
    valToType  2 = Just SignatureDSS
    valToType  3 = Just SignatureECDSA
    valToType  4 = Just SignatureRSApssRSAeSHA256
    valToType  5 = Just SignatureRSApssRSAeSHA384
    valToType  6 = Just SignatureRSApssRSAeSHA512
    valToType  7 = Just SignatureEd25519
    valToType  8 = Just SignatureEd448
    valToType  9 = Just SignatureRSApsspssSHA256
    valToType 10 = Just SignatureRSApsspssSHA384
    valToType 11 = Just SignatureRSApsspssSHA512
    valToType  i = Just (SignatureOther i)

instance EnumSafe16 Group where
    fromEnumSafe16 P256      =  23
    fromEnumSafe16 P384      =  24
    fromEnumSafe16 P521      =  25
    fromEnumSafe16 X25519    =  29
    fromEnumSafe16 X448      =  30
    fromEnumSafe16 FFDHE2048 = 256
    fromEnumSafe16 FFDHE3072 = 257
    fromEnumSafe16 FFDHE4096 = 258
    fromEnumSafe16 FFDHE6144 = 259
    fromEnumSafe16 FFDHE8192 = 260

    toEnumSafe16  23 = Just P256
    toEnumSafe16  24 = Just P384
    toEnumSafe16  25 = Just P521
    toEnumSafe16  29 = Just X25519
    toEnumSafe16  30 = Just X448
    toEnumSafe16 256 = Just FFDHE2048
    toEnumSafe16 257 = Just FFDHE3072
    toEnumSafe16 258 = Just FFDHE4096
    toEnumSafe16 259 = Just FFDHE6144
    toEnumSafe16 260 = Just FFDHE8192
    toEnumSafe16 _   = Nothing
