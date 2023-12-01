{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE PatternSynonyms #-}
{-# OPTIONS_HADDOCK hide #-}

-- |
-- Module      : Network.TLS.Struct
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Struct module contains all definitions and values of the TLS protocol
module Network.TLS.Struct (
    Version (..),
    ConnectionEnd (..),
    CipherType (..),
    CipherData (..),
    ExtensionID (
        ExtensionID,
        EID_ServerName,
        EID_MaxFragmentLength,
        EID_ClientCertificateUrl,
        EID_TrustedCAKeys,
        EID_TruncatedHMAC,
        EID_StatusRequest,
        EID_UserMapping,
        EID_ClientAuthz,
        EID_ServerAuthz,
        EID_CertType,
        EID_SupportedGroups,
        EID_EcPointFormats,
        EID_SRP,
        EID_SignatureAlgorithms,
        EID_SRTP,
        EID_Heartbeat,
        EID_ApplicationLayerProtocolNegotiation,
        EID_StatusRequestv2,
        EID_SignedCertificateTimestamp,
        EID_ClientCertificateType,
        EID_ServerCertificateType,
        EID_Padding,
        EID_EncryptThenMAC,
        EID_ExtendedMasterSecret,
        EID_SessionTicket,
        EID_PreSharedKey,
        EID_EarlyData,
        EID_SupportedVersions,
        EID_Cookie,
        EID_PskKeyExchangeModes,
        EID_CertificateAuthorities,
        EID_OidFilters,
        EID_PostHandshakeAuth,
        EID_SignatureAlgorithmsCert,
        EID_KeyShare,
        EID_QuicTransportParameters,
        EID_SecureRenegotiation
    ),
    ExtensionRaw (..),
    CertificateType (..),
    lastSupportedCertificateType,
    HashAlgorithm (..),
    SignatureAlgorithm (
        SignatureAlgorithm,
        SignatureAnonymous,
        SignatureRSA,
        SignatureDSS,
        SignatureECDSA,
        SignatureRSApssRSAeSHA256,
        SignatureRSApssRSAeSHA384,
        SignatureRSApssRSAeSHA512,
        SignatureEd25519,
        SignatureEd448,
        SignatureRSApsspssSHA256,
        SignatureRSApsspssSHA384,
        SignatureRSApsspssSHA512
    ),
    HashAndSignatureAlgorithm,
    DigitallySigned (..),
    Signature,
    ProtocolType (
        ProtocolType,
        ProtocolType_ChangeCipherSpec,
        ProtocolType_Alert,
        ProtocolType_Handshake,
        ProtocolType_AppData
    ),
    TLSError (..),
    TLSException (..),
    DistinguishedName,
    BigNum (..),
    bigNumToInteger,
    bigNumFromInteger,
    ServerDHParams (..),
    serverDHParamsToParams,
    serverDHParamsToPublic,
    serverDHParamsFrom,
    ServerECDHParams (..),
    ServerRSAParams (..),
    ServerKeyXchgAlgorithmData (..),
    ClientKeyXchgAlgorithmData (..),
    Packet (..),
    Header (..),
    ServerRandom (..),
    ClientRandom (..),
    FinishedData,
    SessionID,
    Session (..),
    SessionData (..),
    AlertLevel (..),
    AlertDescription (..),
    HandshakeType (..),
    Handshake (..),
    TypeValuable,
    valOfType,
    valToType,
    EnumSafe16 (..),
    packetType,
    typeOfHandshake,
) where

import Control.Exception (Exception (..))
import Data.Typeable
import Data.X509 (CertificateChain, DistinguishedName)
import Network.TLS.Crypto
import Network.TLS.Imports
import Network.TLS.Types
import Network.TLS.Util.Serialization

------------------------------------------------------------

data ConnectionEnd = ConnectionServer | ConnectionClient
data CipherType = CipherStream | CipherBlock | CipherAEAD

data CipherData = CipherData
    { cipherDataContent :: ByteString
    , cipherDataMAC :: Maybe ByteString
    , cipherDataPadding :: Maybe (ByteString, Int)
    }
    deriving (Show, Eq)

------------------------------------------------------------

-- | Some of the IANA registered code points for 'CertificateType' are not
-- currently supported by the library.  Nor should they be, they're are either
-- unwise, obsolete or both.  There's no point in conveying these to the user
-- in the client certificate request callback.  The request callback will be
-- filtered to exclude unsupported values.  If the user cannot find a certificate
-- for a supported code point, we'll go ahead without a client certificate and
-- hope for the best, unless the user's callback decides to throw an exception.
data CertificateType
    = -- | TLS10 and up, RFC5246
      CertificateType_RSA_Sign
    | -- | TLS10 and up, RFC5246
      CertificateType_DSS_Sign
    | -- | TLS10 and up, RFC8422
      CertificateType_ECDSA_Sign
    | -- | TLS13 and up, synthetic
      CertificateType_Ed25519_Sign
    | -- | TLS13 and up, synthetic
      -- | None of the below will ever be presented to the callback.  Any future
      -- public key algorithms valid for client certificates go above this line.
      CertificateType_Ed448_Sign
    | CertificateType_RSA_Fixed_DH -- Obsolete, unsupported
    | CertificateType_DSS_Fixed_DH -- Obsolete, unsupported
    | CertificateType_RSA_Ephemeral_DH -- Obsolete, unsupported
    | CertificateType_DSS_Ephemeral_DH -- Obsolete, unsupported
    | CertificateType_fortezza_dms -- Obsolete, unsupported
    | CertificateType_RSA_Fixed_ECDH -- Obsolete, unsupported
    | CertificateType_ECDSA_Fixed_ECDH -- Obsolete, unsupported
    | CertificateType_Unknown Word8 -- Obsolete, unsupported
    deriving (Eq, Ord, Show)

-- | Last supported certificate type, no 'CertificateType that
-- compares greater than this one (based on the 'Ord' instance,
-- not on the wire code point) will be reported to the application
-- via the client certificate request callback.
lastSupportedCertificateType :: CertificateType
lastSupportedCertificateType = CertificateType_ECDSA_Sign

------------------------------------------------------------

data HashAlgorithm
    = HashNone
    | HashMD5
    | HashSHA1
    | HashSHA224
    | HashSHA256
    | HashSHA384
    | HashSHA512
    | HashIntrinsic
    | HashOther Word8
    deriving (Show, Eq)

------------------------------------------------------------

newtype SignatureAlgorithm = SignatureAlgorithm Word8 deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern SignatureAnonymous        :: SignatureAlgorithm
pattern SignatureAnonymous         = SignatureAlgorithm 0
pattern SignatureRSA              :: SignatureAlgorithm
pattern SignatureRSA               = SignatureAlgorithm 1
pattern SignatureDSS              :: SignatureAlgorithm
pattern SignatureDSS               = SignatureAlgorithm 2
pattern SignatureECDSA            :: SignatureAlgorithm
pattern SignatureECDSA             = SignatureAlgorithm 3
pattern SignatureRSApssRSAeSHA256 :: SignatureAlgorithm
pattern SignatureRSApssRSAeSHA256  = SignatureAlgorithm 4
pattern SignatureRSApssRSAeSHA384 :: SignatureAlgorithm
pattern SignatureRSApssRSAeSHA384  = SignatureAlgorithm 5
pattern SignatureRSApssRSAeSHA512 :: SignatureAlgorithm
pattern SignatureRSApssRSAeSHA512  = SignatureAlgorithm 6
pattern SignatureEd25519          :: SignatureAlgorithm
pattern SignatureEd25519           = SignatureAlgorithm 7
pattern SignatureEd448            :: SignatureAlgorithm
pattern SignatureEd448             = SignatureAlgorithm 8
pattern SignatureRSApsspssSHA256  :: SignatureAlgorithm
pattern SignatureRSApsspssSHA256   = SignatureAlgorithm 9
pattern SignatureRSApsspssSHA384  :: SignatureAlgorithm
pattern SignatureRSApsspssSHA384   = SignatureAlgorithm 10
pattern SignatureRSApsspssSHA512  :: SignatureAlgorithm
pattern SignatureRSApsspssSHA512   = SignatureAlgorithm 11

instance Show SignatureAlgorithm where
    show SignatureAnonymous        = "SignatureAnonymous"
    show SignatureRSA              = "SignatureRSA"
    show SignatureDSS              = "SignatureDSS"
    show SignatureECDSA            = "SignatureECDSA"
    show SignatureRSApssRSAeSHA256 = "SignatureRSApssRSAeSHA256"
    show SignatureRSApssRSAeSHA384 = "SignatureRSApssRSAeSHA384"
    show SignatureRSApssRSAeSHA512 = "SignatureRSApssRSAeSHA512"
    show SignatureEd25519          = "SignatureEd25519"
    show SignatureEd448            = "SignatureEd448"
    show SignatureRSApsspssSHA256  = "SignatureRSApsspssSHA256"
    show SignatureRSApsspssSHA384  = "SignatureRSApsspssSHA384"
    show SignatureRSApsspssSHA512  = "SignatureRSApsspssSHA512"
    show (SignatureAlgorithm x)    = "SignatureAlgorithm " ++ show x
{- FOURMOLU_ENABLE -}

------------------------------------------------------------

type HashAndSignatureAlgorithm = (HashAlgorithm, SignatureAlgorithm)

------------------------------------------------------------

type Signature = ByteString

data DigitallySigned = DigitallySigned (Maybe HashAndSignatureAlgorithm) Signature
    deriving (Show, Eq)

newtype ProtocolType = ProtocolType Word8 deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern ProtocolType_ChangeCipherSpec :: ProtocolType
pattern ProtocolType_ChangeCipherSpec  = ProtocolType 20

pattern ProtocolType_Alert            :: ProtocolType
pattern ProtocolType_Alert             = ProtocolType 21

pattern ProtocolType_Handshake        :: ProtocolType
pattern ProtocolType_Handshake         = ProtocolType 22

pattern ProtocolType_AppData          :: ProtocolType
pattern ProtocolType_AppData           = ProtocolType 23

instance Show ProtocolType where
    show ProtocolType_ChangeCipherSpec = "ChangeCipherSpec"
    show ProtocolType_Alert            = "Alert"
    show ProtocolType_Handshake        = "Handshake"
    show ProtocolType_AppData          = "AppData"
    show (ProtocolType x)              = "ProtocolType " ++ show x
{- FOURMOLU_ENABLE -}

-- | TLSError that might be returned through the TLS stack.
--
-- Prior to version 1.8.0, this type had an @Exception@ instance.
-- In version 1.8.0, this instance was removed, and functions in
-- this library now only throw 'TLSException'.
data TLSError
    = -- | mainly for instance of Error
      Error_Misc String
    | -- | A fatal error condition was encountered at a low level.  The
      -- elements of the tuple give (freeform text description, structured
      -- error description).
      Error_Protocol String AlertDescription
    | -- | A non-fatal error condition was encountered at a low level at a low
      -- level.  The elements of the tuple give (freeform text description,
      -- structured error description).
      Error_Protocol_Warning String AlertDescription
    | Error_Certificate String
    | -- | handshake policy failed.
      Error_HandshakePolicy String
    | Error_EOF
    | Error_Packet String
    | Error_Packet_unexpected String String
    | Error_Packet_Parsing String
    deriving (Eq, Show, Typeable)

-- | TLS Exceptions. Some of the data constructors indicate incorrect use of
--   the library, and the documentation for those data constructors calls
--   this out. The others wrap 'TLSError' with some kind of context to explain
--   when the exception occurred.
data TLSException
    = -- | Early termination exception with the reason and the error associated
      Terminated Bool String TLSError
    | -- | Handshake failed for the reason attached.
      HandshakeFailed TLSError
    | -- | Failure occurred while sending or receiving data after the
      --   TLS handshake succeeded.
      PostHandshake TLSError
    | -- | Lifts a 'TLSError' into 'TLSException' without provided any context
      --   around when the error happened.
      Uncontextualized TLSError
    | -- | Usage error when the connection has not been established
      --   and the user is trying to send or receive data.
      --   Indicates that this library has been used incorrectly.
      ConnectionNotEstablished
    | -- | Expected that a TLS handshake had already taken place, but no TLS
      --   handshake had occurred.
      --   Indicates that this library has been used incorrectly.
      MissingHandshake
    deriving (Show, Eq, Typeable)

instance Exception TLSException

data Packet
    = Handshake [Handshake]
    | Alert [(AlertLevel, AlertDescription)]
    | ChangeCipherSpec
    | AppData ByteString
    deriving (Show, Eq)

data Header = Header ProtocolType Version Word16 deriving (Show, Eq)

newtype ServerRandom = ServerRandom {unServerRandom :: ByteString}
    deriving (Show, Eq)
newtype ClientRandom = ClientRandom {unClientRandom :: ByteString}
    deriving (Show, Eq)
newtype Session = Session (Maybe SessionID) deriving (Show, Eq)

type FinishedData = ByteString

-- | Identifier of a TLS extension.
--   <http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.txt>
newtype ExtensionID = ExtensionID Word16 deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern EID_ServerName                          :: ExtensionID -- RFC6066
pattern EID_ServerName                           = ExtensionID 0x0
pattern EID_MaxFragmentLength                   :: ExtensionID -- RFC6066
pattern EID_MaxFragmentLength                    = ExtensionID 0x1
pattern EID_ClientCertificateUrl                :: ExtensionID -- RFC6066
pattern EID_ClientCertificateUrl                 = ExtensionID 0x2
pattern EID_TrustedCAKeys                       :: ExtensionID -- RFC6066
pattern EID_TrustedCAKeys                        = ExtensionID 0x3
pattern EID_TruncatedHMAC                       :: ExtensionID -- RFC6066
pattern EID_TruncatedHMAC                        = ExtensionID 0x4
pattern EID_StatusRequest                       :: ExtensionID -- RFC6066
pattern EID_StatusRequest                        = ExtensionID 0x5
pattern EID_UserMapping                         :: ExtensionID -- RFC4681
pattern EID_UserMapping                          = ExtensionID 0x6
pattern EID_ClientAuthz                         :: ExtensionID -- RFC5878
pattern EID_ClientAuthz                          = ExtensionID 0x7
pattern EID_ServerAuthz                         :: ExtensionID -- RFC5878
pattern EID_ServerAuthz                          = ExtensionID 0x8
pattern EID_CertType                            :: ExtensionID -- RFC6091
pattern EID_CertType                             = ExtensionID 0x9
pattern EID_SupportedGroups                     :: ExtensionID -- RFC8422,8446
pattern EID_SupportedGroups                      = ExtensionID 0xa
pattern EID_EcPointFormats                      :: ExtensionID -- RFC4492
pattern EID_EcPointFormats                       = ExtensionID 0xb
pattern EID_SRP                                 :: ExtensionID -- RFC5054
pattern EID_SRP                                  = ExtensionID 0xc
pattern EID_SignatureAlgorithms                 :: ExtensionID -- RFC5246,8446
pattern EID_SignatureAlgorithms                  = ExtensionID 0xd
pattern EID_SRTP                                :: ExtensionID -- RFC5764
pattern EID_SRTP                                 = ExtensionID 0xe
pattern EID_Heartbeat                           :: ExtensionID -- RFC6520
pattern EID_Heartbeat                            = ExtensionID 0xf
pattern EID_ApplicationLayerProtocolNegotiation :: ExtensionID -- RFC7301
pattern EID_ApplicationLayerProtocolNegotiation  = ExtensionID 0x10
pattern EID_StatusRequestv2                     :: ExtensionID -- RFC6961
pattern EID_StatusRequestv2                      = ExtensionID 0x11
pattern EID_SignedCertificateTimestamp          :: ExtensionID -- RFC6962
pattern EID_SignedCertificateTimestamp           = ExtensionID 0x12
pattern EID_ClientCertificateType               :: ExtensionID -- RFC7250
pattern EID_ClientCertificateType                = ExtensionID 0x13
pattern EID_ServerCertificateType               :: ExtensionID -- RFC7250
pattern EID_ServerCertificateType                = ExtensionID 0x14
pattern EID_Padding                             :: ExtensionID -- RFC5246
pattern EID_Padding                              = ExtensionID 0x15
pattern EID_EncryptThenMAC                      :: ExtensionID -- RFC7366
pattern EID_EncryptThenMAC                       = ExtensionID 0x16
pattern EID_ExtendedMasterSecret                :: ExtensionID -- REF7627
pattern EID_ExtendedMasterSecret                 = ExtensionID 0x17
pattern EID_SessionTicket                       :: ExtensionID -- RFC4507
pattern EID_SessionTicket                        = ExtensionID 0x23
pattern EID_PreSharedKey                        :: ExtensionID -- RFC8446
pattern EID_PreSharedKey                         = ExtensionID 0x29
pattern EID_EarlyData                           :: ExtensionID -- RFC8446
pattern EID_EarlyData                            = ExtensionID 0x2a
pattern EID_SupportedVersions                   :: ExtensionID -- RFC8446
pattern EID_SupportedVersions                    = ExtensionID 0x2b
pattern EID_Cookie                              :: ExtensionID -- RFC8446
pattern EID_Cookie                               = ExtensionID 0x2c
pattern EID_PskKeyExchangeModes                 :: ExtensionID -- RFC8446
pattern EID_PskKeyExchangeModes                  = ExtensionID 0x2d
pattern EID_CertificateAuthorities              :: ExtensionID -- RFC8446
pattern EID_CertificateAuthorities               = ExtensionID 0x2f
pattern EID_OidFilters                          :: ExtensionID -- RFC8446
pattern EID_OidFilters                           = ExtensionID 0x30
pattern EID_PostHandshakeAuth                   :: ExtensionID -- RFC8446
pattern EID_PostHandshakeAuth                    = ExtensionID 0x31
pattern EID_SignatureAlgorithmsCert             :: ExtensionID -- RFC8446
pattern EID_SignatureAlgorithmsCert              = ExtensionID 0x32
pattern EID_KeyShare                            :: ExtensionID -- RFC8446
pattern EID_KeyShare                             = ExtensionID 0x33
pattern EID_QuicTransportParameters             :: ExtensionID -- RFC9001
pattern EID_QuicTransportParameters              = ExtensionID 0x39
pattern EID_SecureRenegotiation                 :: ExtensionID -- RFC5746
pattern EID_SecureRenegotiation                  = ExtensionID 0xff01

instance Show ExtensionID where
    show EID_ServerName              = "ServerName"
    show EID_MaxFragmentLength       = "MaxFragmentLength"
    show EID_ClientCertificateUrl    = "ClientCertificateUrl"
    show EID_TrustedCAKeys           = "TrustedCAKeys"
    show EID_TruncatedHMAC           = "TruncatedHMAC"
    show EID_StatusRequest           = "StatusRequest"
    show EID_UserMapping             = "UserMapping"
    show EID_ClientAuthz             = "ClientAuthz"
    show EID_ServerAuthz             = "ServerAuthz"
    show EID_CertType                = "CertType"
    show EID_SupportedGroups         = "SupportedGroups"
    show EID_EcPointFormats          = "EcPointFormats"
    show EID_SRP                     = "SRP"
    show EID_SignatureAlgorithms     = "SignatureAlgorithms"
    show EID_SRTP                    = "SRTP"
    show EID_Heartbeat               = "Heartbeat"
    show EID_ApplicationLayerProtocolNegotiation = "ApplicationLayerProtocolNegotiation"
    show EID_StatusRequestv2         = "StatusRequestv2"
    show EID_SignedCertificateTimestamp = "SignedCertificateTimestamp"
    show EID_ClientCertificateType   = "ClientCertificateType"
    show EID_ServerCertificateType   = "ServerCertificateType"
    show EID_Padding                 = "Padding"
    show EID_EncryptThenMAC          = "EncryptThenMAC"
    show EID_ExtendedMasterSecret    = "ExtendedMasterSecret"
    show EID_SessionTicket           = "SessionTicket"
    show EID_PreSharedKey            = "PreSharedKey"
    show EID_EarlyData               = "EarlyData"
    show EID_SupportedVersions       = "SupportedVersions"
    show EID_Cookie                  = "Cookie"
    show EID_PskKeyExchangeModes     = "PskKeyExchangeModes"
    show EID_CertificateAuthorities  = "CertificateAuthorities"
    show EID_OidFilters              = "OidFilters"
    show EID_PostHandshakeAuth       = "PostHandshakeAuth"
    show EID_SignatureAlgorithmsCert = "SignatureAlgorithmsCert"
    show EID_KeyShare                = "KeyShare"
    show EID_QuicTransportParameters = "QuicTransportParameters"
    show EID_SecureRenegotiation     = "SecureRenegotiation"
    show (ExtensionID x)         = "ExtensionID " ++ show x
{- FOURMOLU_ENABLE -}

-- | The raw content of a TLS extension.
data ExtensionRaw = ExtensionRaw ExtensionID ByteString
    deriving (Eq)

instance Show ExtensionRaw where
    show (ExtensionRaw eid bs) = "ExtensionRaw " ++ show eid ++ " " ++ showBytesHex bs

data AlertLevel
    = AlertLevel_Warning
    | AlertLevel_Fatal
    deriving (Show, Eq)

data AlertDescription
    = CloseNotify
    | UnexpectedMessage
    | BadRecordMac
    | -- | deprecated alert, should never be sent by compliant implementation
      DecryptionFailed
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
    deriving (Show, Eq)

data HandshakeType
    = HandshakeType_HelloRequest
    | HandshakeType_ClientHello
    | HandshakeType_ServerHello
    | HandshakeType_Certificate
    | HandshakeType_ServerKeyXchg
    | HandshakeType_CertRequest
    | HandshakeType_ServerHelloDone
    | HandshakeType_CertVerify
    | HandshakeType_ClientKeyXchg
    | HandshakeType_Finished
    deriving (Show, Eq)

newtype BigNum = BigNum ByteString
    deriving (Show, Eq)

bigNumToInteger :: BigNum -> Integer
bigNumToInteger (BigNum b) = os2ip b

bigNumFromInteger :: Integer -> BigNum
bigNumFromInteger i = BigNum $ i2osp i

data ServerDHParams = ServerDHParams
    { serverDHParams_p :: BigNum
    , serverDHParams_g :: BigNum
    , serverDHParams_y :: BigNum
    }
    deriving (Show, Eq)

serverDHParamsFrom :: DHParams -> DHPublic -> ServerDHParams
serverDHParamsFrom params dhPub =
    ServerDHParams
        (bigNumFromInteger $ dhParamsGetP params)
        (bigNumFromInteger $ dhParamsGetG params)
        (bigNumFromInteger $ dhUnwrapPublic dhPub)

serverDHParamsToParams :: ServerDHParams -> DHParams
serverDHParamsToParams serverParams =
    dhParams
        (bigNumToInteger $ serverDHParams_p serverParams)
        (bigNumToInteger $ serverDHParams_g serverParams)

serverDHParamsToPublic :: ServerDHParams -> DHPublic
serverDHParamsToPublic serverParams =
    dhPublic (bigNumToInteger $ serverDHParams_y serverParams)

data ServerECDHParams = ServerECDHParams Group GroupPublic
    deriving (Show, Eq)

data ServerRSAParams = ServerRSAParams
    { rsa_modulus :: Integer
    , rsa_exponent :: Integer
    }
    deriving (Show, Eq)

data ServerKeyXchgAlgorithmData
    = SKX_DH_Anon ServerDHParams
    | SKX_DHE_DSS ServerDHParams DigitallySigned
    | SKX_DHE_RSA ServerDHParams DigitallySigned
    | SKX_ECDHE_RSA ServerECDHParams DigitallySigned
    | SKX_ECDHE_ECDSA ServerECDHParams DigitallySigned
    | SKX_RSA (Maybe ServerRSAParams)
    | SKX_DH_DSS (Maybe ServerRSAParams)
    | SKX_DH_RSA (Maybe ServerRSAParams)
    | SKX_Unparsed ByteString -- if we parse the server key xchg before knowing the actual cipher, we end up with this structure.
    | SKX_Unknown ByteString
    deriving (Show, Eq)

data ClientKeyXchgAlgorithmData
    = CKX_RSA ByteString
    | CKX_DH DHPublic
    | CKX_ECDH ByteString
    deriving (Show, Eq)

type DeprecatedRecord = ByteString

data Handshake
    = ClientHello
        !Version
        !ClientRandom
        !Session
        ![CipherID]
        ![CompressionID]
        [ExtensionRaw]
        (Maybe DeprecatedRecord)
    | ServerHello
        !Version
        !ServerRandom
        !Session
        !CipherID
        !CompressionID
        [ExtensionRaw]
    | Certificates CertificateChain
    | HelloRequest
    | ServerHelloDone
    | ClientKeyXchg ClientKeyXchgAlgorithmData
    | ServerKeyXchg ServerKeyXchgAlgorithmData
    | CertRequest
        [CertificateType]
        (Maybe [HashAndSignatureAlgorithm])
        [DistinguishedName]
    | CertVerify DigitallySigned
    | Finished FinishedData
    deriving (Show, Eq)

packetType :: Packet -> ProtocolType
packetType (Handshake _) = ProtocolType_Handshake
packetType (Alert _) = ProtocolType_Alert
packetType ChangeCipherSpec = ProtocolType_ChangeCipherSpec
packetType (AppData _) = ProtocolType_AppData

typeOfHandshake :: Handshake -> HandshakeType
typeOfHandshake ClientHello{} = HandshakeType_ClientHello
typeOfHandshake ServerHello{} = HandshakeType_ServerHello
typeOfHandshake Certificates{} = HandshakeType_Certificate
typeOfHandshake HelloRequest = HandshakeType_HelloRequest
typeOfHandshake ServerHelloDone = HandshakeType_ServerHelloDone
typeOfHandshake ClientKeyXchg{} = HandshakeType_ClientKeyXchg
typeOfHandshake ServerKeyXchg{} = HandshakeType_ServerKeyXchg
typeOfHandshake CertRequest{} = HandshakeType_CertRequest
typeOfHandshake CertVerify{} = HandshakeType_CertVerify
typeOfHandshake Finished{} = HandshakeType_Finished

class TypeValuable a where
    valOfType :: a -> Word8
    valToType :: Word8 -> Maybe a

class EnumSafe16 a where
    fromEnumSafe16 :: a -> Word16
    toEnumSafe16 :: Word16 -> Maybe a

instance TypeValuable ConnectionEnd where
    valOfType ConnectionServer = 0
    valOfType ConnectionClient = 1

    valToType 0 = Just ConnectionServer
    valToType 1 = Just ConnectionClient
    valToType _ = Nothing

instance TypeValuable CipherType where
    valOfType CipherStream = 0
    valOfType CipherBlock = 1
    valOfType CipherAEAD = 2

    valToType 0 = Just CipherStream
    valToType 1 = Just CipherBlock
    valToType 2 = Just CipherAEAD
    valToType _ = Nothing

instance TypeValuable HandshakeType where
    valOfType HandshakeType_HelloRequest = 0
    valOfType HandshakeType_ClientHello = 1
    valOfType HandshakeType_ServerHello = 2
    valOfType HandshakeType_Certificate = 11
    valOfType HandshakeType_ServerKeyXchg = 12
    valOfType HandshakeType_CertRequest = 13
    valOfType HandshakeType_ServerHelloDone = 14
    valOfType HandshakeType_CertVerify = 15
    valOfType HandshakeType_ClientKeyXchg = 16
    valOfType HandshakeType_Finished = 20

    valToType 0 = Just HandshakeType_HelloRequest
    valToType 1 = Just HandshakeType_ClientHello
    valToType 2 = Just HandshakeType_ServerHello
    valToType 11 = Just HandshakeType_Certificate
    valToType 12 = Just HandshakeType_ServerKeyXchg
    valToType 13 = Just HandshakeType_CertRequest
    valToType 14 = Just HandshakeType_ServerHelloDone
    valToType 15 = Just HandshakeType_CertVerify
    valToType 16 = Just HandshakeType_ClientKeyXchg
    valToType 20 = Just HandshakeType_Finished
    valToType _ = Nothing

instance TypeValuable AlertLevel where
    valOfType AlertLevel_Warning = 1
    valOfType AlertLevel_Fatal = 2

    valToType 1 = Just AlertLevel_Warning
    valToType 2 = Just AlertLevel_Fatal
    valToType _ = Nothing

instance TypeValuable AlertDescription where
    valOfType CloseNotify = 0
    valOfType UnexpectedMessage = 10
    valOfType BadRecordMac = 20
    valOfType DecryptionFailed = 21
    valOfType RecordOverflow = 22
    valOfType DecompressionFailure = 30
    valOfType HandshakeFailure = 40
    valOfType BadCertificate = 42
    valOfType UnsupportedCertificate = 43
    valOfType CertificateRevoked = 44
    valOfType CertificateExpired = 45
    valOfType CertificateUnknown = 46
    valOfType IllegalParameter = 47
    valOfType UnknownCa = 48
    valOfType AccessDenied = 49
    valOfType DecodeError = 50
    valOfType DecryptError = 51
    valOfType ExportRestriction = 60
    valOfType ProtocolVersion = 70
    valOfType InsufficientSecurity = 71
    valOfType InternalError = 80
    valOfType InappropriateFallback = 86
    valOfType UserCanceled = 90
    valOfType NoRenegotiation = 100
    valOfType MissingExtension = 109
    valOfType UnsupportedExtension = 110
    valOfType CertificateUnobtainable = 111
    valOfType UnrecognizedName = 112
    valOfType BadCertificateStatusResponse = 113
    valOfType BadCertificateHashValue = 114
    valOfType UnknownPskIdentity = 115
    valOfType CertificateRequired = 116
    valOfType NoApplicationProtocol = 120

    valToType 0 = Just CloseNotify
    valToType 10 = Just UnexpectedMessage
    valToType 20 = Just BadRecordMac
    valToType 21 = Just DecryptionFailed
    valToType 22 = Just RecordOverflow
    valToType 30 = Just DecompressionFailure
    valToType 40 = Just HandshakeFailure
    valToType 42 = Just BadCertificate
    valToType 43 = Just UnsupportedCertificate
    valToType 44 = Just CertificateRevoked
    valToType 45 = Just CertificateExpired
    valToType 46 = Just CertificateUnknown
    valToType 47 = Just IllegalParameter
    valToType 48 = Just UnknownCa
    valToType 49 = Just AccessDenied
    valToType 50 = Just DecodeError
    valToType 51 = Just DecryptError
    valToType 60 = Just ExportRestriction
    valToType 70 = Just ProtocolVersion
    valToType 71 = Just InsufficientSecurity
    valToType 80 = Just InternalError
    valToType 86 = Just InappropriateFallback
    valToType 90 = Just UserCanceled
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
    valToType _ = Nothing

instance TypeValuable CertificateType where
    valOfType CertificateType_RSA_Sign = 1
    valOfType CertificateType_ECDSA_Sign = 64
    valOfType CertificateType_DSS_Sign = 2
    valOfType CertificateType_RSA_Fixed_DH = 3
    valOfType CertificateType_DSS_Fixed_DH = 4
    valOfType CertificateType_RSA_Ephemeral_DH = 5
    valOfType CertificateType_DSS_Ephemeral_DH = 6
    valOfType CertificateType_fortezza_dms = 20
    valOfType CertificateType_RSA_Fixed_ECDH = 65
    valOfType CertificateType_ECDSA_Fixed_ECDH = 66
    valOfType (CertificateType_Unknown i) = i
    -- \| There are no code points that map to the below synthetic types, these
    -- are inferred indirectly from the @signature_algorithms@ extension of the
    -- TLS 1.3 @CertificateRequest@ message.  the value assignments are there
    -- only to avoid partial function warnings.
    valOfType CertificateType_Ed25519_Sign = 0
    valOfType CertificateType_Ed448_Sign = 0

    valToType 1 = Just CertificateType_RSA_Sign
    valToType 2 = Just CertificateType_DSS_Sign
    valToType 3 = Just CertificateType_RSA_Fixed_DH
    valToType 4 = Just CertificateType_DSS_Fixed_DH
    valToType 5 = Just CertificateType_RSA_Ephemeral_DH
    valToType 6 = Just CertificateType_DSS_Ephemeral_DH
    valToType 20 = Just CertificateType_fortezza_dms
    valToType 64 = Just CertificateType_ECDSA_Sign
    valToType 65 = Just CertificateType_RSA_Fixed_ECDH
    valToType 66 = Just CertificateType_ECDSA_Fixed_ECDH
    valToType i = Just (CertificateType_Unknown i)

-- \| There are no code points that map to the below synthetic types, these
-- are inferred indirectly from the @signature_algorithms@ extension of the
-- TLS 1.3 @CertificateRequest@ message.
-- @
-- CertificateType_Ed25519_Sign
-- CertificateType_Ed448_Sign
-- @

instance TypeValuable HashAlgorithm where
    valOfType HashNone = 0
    valOfType HashMD5 = 1
    valOfType HashSHA1 = 2
    valOfType HashSHA224 = 3
    valOfType HashSHA256 = 4
    valOfType HashSHA384 = 5
    valOfType HashSHA512 = 6
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
