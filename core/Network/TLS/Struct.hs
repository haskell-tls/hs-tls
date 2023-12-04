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
    CipherData (..),
    ExtensionID (
        ..,
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
    CertificateType (
        CertificateType,
        CertificateType_RSA_Sign,
        CertificateType_DSA_Sign,
        CertificateType_ECDSA_Sign,
        CertificateType_Ed25519_Sign,
        CertificateType_Ed448_Sign
    ),
    fromCertificateType,
    lastSupportedCertificateType,
    HashAlgorithm (
        ..,
        HashNone,
        HashMD5,
        HashSHA1,
        HashSHA224,
        HashSHA256,
        HashSHA384,
        HashSHA512,
        HashIntrinsic
    ),
    SignatureAlgorithm (
        ..,
        SignatureAnonymous,
        SignatureRSA,
        SignatureDSA,
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
        ..,
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
    AlertLevel (
        ..,
        AlertLevel_Warning,
        AlertLevel_Fatal
    ),
    AlertDescription (
        ..,
        CloseNotify,
        UnexpectedMessage,
        BadRecordMac,
        DecryptionFailed,
        RecordOverflow,
        DecompressionFailure,
        HandshakeFailure,
        BadCertificate,
        UnsupportedCertificate,
        CertificateRevoked,
        CertificateExpired,
        CertificateUnknown,
        IllegalParameter,
        UnknownCa,
        AccessDenied,
        DecodeError,
        DecryptError,
        ExportRestriction,
        ProtocolVersion,
        InsufficientSecurity,
        InternalError,
        InappropriateFallback,
        UserCanceled,
        NoRenegotiation,
        MissingExtension,
        UnsupportedExtension,
        CertificateUnobtainable,
        UnrecognizedName,
        BadCertificateStatusResponse,
        BadCertificateHashValue,
        UnknownPskIdentity,
        CertificateRequired,
        NoApplicationProtocol
    ),
    HandshakeType (
        ..,
        HandshakeType_HelloRequest,
        HandshakeType_ClientHello,
        HandshakeType_ServerHello,
        HandshakeType_NewSessionTicket,
        HandshakeType_EndOfEarlyData,
        HandshakeType_EncryptedExtensions,
        HandshakeType_Certificate,
        HandshakeType_ServerKeyXchg,
        HandshakeType_CertRequest,
        HandshakeType_ServerHelloDone,
        HandshakeType_CertVerify,
        HandshakeType_ClientKeyXchg,
        HandshakeType_Finished,
        HandshakeType_KeyUpdate
    ),
    Handshake (..),
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

----------------------------------------------------------------

data CipherData = CipherData
    { cipherDataContent :: ByteString
    , cipherDataMAC :: Maybe ByteString
    , cipherDataPadding :: Maybe (ByteString, Int)
    }
    deriving (Show, Eq)

----------------------------------------------------------------

-- | Some of the IANA registered code points for 'CertificateType' are not
-- currently supported by the library.  Nor should they be, they're are either
-- unwise, obsolete or both.  There's no point in conveying these to the user
-- in the client certificate request callback.  The request callback will be
-- filtered to exclude unsupported values.  If the user cannot find a certificate
-- for a supported code point, we'll go ahead without a client certificate and
-- hope for the best, unless the user's callback decides to throw an exception.
newtype CertificateType = CertificateType {fromCertificateType :: Word8}
    deriving (Eq, Ord)

{- FOURMOLU_DISABLE -}
-- | TLS10 and up, RFC5246
pattern CertificateType_RSA_Sign     :: CertificateType
pattern CertificateType_RSA_Sign      = CertificateType 1
-- | TLS10 and up, RFC5246
pattern CertificateType_DSA_Sign     :: CertificateType
pattern CertificateType_DSA_Sign      = CertificateType 2
-- | TLS10 and up, RFC8422
pattern CertificateType_ECDSA_Sign   :: CertificateType
pattern CertificateType_ECDSA_Sign    = CertificateType 64
-- \| There are no code points that map to the below synthetic types, these
-- are inferred indirectly from the @signature_algorithms@ extension of the
-- TLS 1.3 @CertificateRequest@ message.  the value assignments are there
-- only to avoid partial function warnings.
pattern CertificateType_Ed25519_Sign :: CertificateType
pattern CertificateType_Ed25519_Sign  = CertificateType 254 -- fixme: dummy value
pattern CertificateType_Ed448_Sign   :: CertificateType
pattern CertificateType_Ed448_Sign    = CertificateType 255 -- fixme:  dummy value

instance Show CertificateType where
    show CertificateType_RSA_Sign     = "CertificateType_RSA_Sign"
    show CertificateType_DSA_Sign     = "CertificateType_DSA_Sign"
    show CertificateType_ECDSA_Sign   = "CertificateType_ECDSA_Sign"
    show CertificateType_Ed25519_Sign = "CertificateType_Ed25519_Sign"
    show CertificateType_Ed448_Sign   = "CertificateType_Ed448_Sign"
    show (CertificateType x)          = "CertificateType " ++ show x
{- FOURMOLU_ENABLE -}

-- | Last supported certificate type, no 'CertificateType that
-- compares greater than this one (based on the 'Ord' instance,
-- not on the wire code point) will be reported to the application
-- via the client certificate request callback.
lastSupportedCertificateType :: CertificateType
lastSupportedCertificateType = CertificateType_ECDSA_Sign

------------------------------------------------------------

newtype HashAlgorithm = HashAlgorithm {fromHashAlgorithm :: Word8}
    deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern HashNone      :: HashAlgorithm
pattern HashNone       = HashAlgorithm 0
pattern HashMD5       :: HashAlgorithm
pattern HashMD5        = HashAlgorithm 1
pattern HashSHA1      :: HashAlgorithm
pattern HashSHA1       = HashAlgorithm 2
pattern HashSHA224    :: HashAlgorithm
pattern HashSHA224     = HashAlgorithm 3
pattern HashSHA256    :: HashAlgorithm
pattern HashSHA256     = HashAlgorithm 4
pattern HashSHA384    :: HashAlgorithm
pattern HashSHA384     = HashAlgorithm 5
pattern HashSHA512    :: HashAlgorithm
pattern HashSHA512     = HashAlgorithm 6
pattern HashIntrinsic :: HashAlgorithm
pattern HashIntrinsic  = HashAlgorithm 8

instance Show HashAlgorithm where
    show HashNone          = "HashNone"
    show HashMD5           = "HashMD5"
    show HashSHA1          = "HashSHA1"
    show HashSHA224        = "HashSHA224"
    show HashSHA256        = "HashSHA256"
    show HashSHA384        = "HashSHA384"
    show HashSHA512        = "HashSHA512"
    show HashIntrinsic     = "HashIntrinsic"
    show (HashAlgorithm x) = "HashAlgorithm " ++ show x
{- FOURMOLU_ENABLE -}

------------------------------------------------------------

newtype SignatureAlgorithm = SignatureAlgorithm {fromSignatureAlgorithm :: Word8}
    deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern SignatureAnonymous        :: SignatureAlgorithm
pattern SignatureAnonymous         = SignatureAlgorithm 0
pattern SignatureRSA              :: SignatureAlgorithm
pattern SignatureRSA               = SignatureAlgorithm 1
pattern SignatureDSA              :: SignatureAlgorithm
pattern SignatureDSA               = SignatureAlgorithm 2
pattern SignatureECDSA            :: SignatureAlgorithm
pattern SignatureECDSA             = SignatureAlgorithm 3
-- TLS 1.3 from here
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
    show SignatureDSA              = "SignatureDSA"
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

----------------------------------------------------------------

newtype ProtocolType = ProtocolType {fromProtocolType :: Word8} deriving (Eq)

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

----------------------------------------------------------------

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

----------------------------------------------------------------

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

----------------------------------------------------------------

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

----------------------------------------------------------------

-- | Identifier of a TLS extension.
--   <http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.txt>
newtype ExtensionID = ExtensionID {fromExtensionID :: Word16} deriving (Eq)

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

----------------------------------------------------------------

-- | The raw content of a TLS extension.
data ExtensionRaw = ExtensionRaw ExtensionID ByteString
    deriving (Eq)

instance Show ExtensionRaw where
    show (ExtensionRaw eid bs) = "ExtensionRaw " ++ show eid ++ " " ++ showBytesHex bs

----------------------------------------------------------------

newtype AlertLevel = AlertLevel {fromAlertLevel :: Word8} deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern AlertLevel_Warning :: AlertLevel
pattern AlertLevel_Warning  = AlertLevel 1
pattern AlertLevel_Fatal   :: AlertLevel
pattern AlertLevel_Fatal    = AlertLevel 2

instance Show AlertLevel where
    show AlertLevel_Warning = "AlertLevel_Warning"
    show AlertLevel_Fatal   = "AlertLevel_Fatal"
    show (AlertLevel x)     = "AlertLevel " ++ show x
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

newtype AlertDescription = AlertDescription {fromAlertDescription :: Word8}
    deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern CloseNotify                  :: AlertDescription
pattern CloseNotify                   = AlertDescription 0
pattern UnexpectedMessage            :: AlertDescription
pattern UnexpectedMessage             = AlertDescription 10
pattern BadRecordMac                 :: AlertDescription
pattern BadRecordMac                  = AlertDescription 20
pattern DecryptionFailed             :: AlertDescription
pattern DecryptionFailed              = AlertDescription 21
pattern RecordOverflow               :: AlertDescription
pattern RecordOverflow                = AlertDescription 22
pattern DecompressionFailure         :: AlertDescription
pattern DecompressionFailure          = AlertDescription 30
pattern HandshakeFailure             :: AlertDescription
pattern HandshakeFailure              = AlertDescription 40
pattern BadCertificate               :: AlertDescription
pattern BadCertificate                = AlertDescription 42
pattern UnsupportedCertificate       :: AlertDescription
pattern UnsupportedCertificate        = AlertDescription 43
pattern CertificateRevoked           :: AlertDescription
pattern CertificateRevoked            = AlertDescription 44
pattern CertificateExpired           :: AlertDescription
pattern CertificateExpired            = AlertDescription 45
pattern CertificateUnknown           :: AlertDescription
pattern CertificateUnknown            = AlertDescription 46
pattern IllegalParameter             :: AlertDescription
pattern IllegalParameter              = AlertDescription 47
pattern UnknownCa                    :: AlertDescription
pattern UnknownCa                     = AlertDescription 48
pattern AccessDenied                 :: AlertDescription
pattern AccessDenied                  = AlertDescription 49
pattern DecodeError                  :: AlertDescription
pattern DecodeError                   = AlertDescription 50
pattern DecryptError                 :: AlertDescription
pattern DecryptError                  = AlertDescription 51
pattern ExportRestriction            :: AlertDescription
pattern ExportRestriction             = AlertDescription 60
pattern ProtocolVersion              :: AlertDescription
pattern ProtocolVersion               = AlertDescription 70
pattern InsufficientSecurity         :: AlertDescription
pattern InsufficientSecurity          = AlertDescription 71
pattern InternalError                :: AlertDescription
pattern InternalError                 = AlertDescription 80
pattern InappropriateFallback        :: AlertDescription
pattern InappropriateFallback         = AlertDescription 86  -- RFC7507
pattern UserCanceled                 :: AlertDescription
pattern UserCanceled                  = AlertDescription 90
pattern NoRenegotiation              :: AlertDescription
pattern NoRenegotiation               = AlertDescription 100
pattern MissingExtension             :: AlertDescription
pattern MissingExtension              = AlertDescription 109
pattern UnsupportedExtension         :: AlertDescription
pattern UnsupportedExtension          = AlertDescription 110
pattern CertificateUnobtainable      :: AlertDescription
pattern CertificateUnobtainable       = AlertDescription 111
pattern UnrecognizedName             :: AlertDescription
pattern UnrecognizedName              = AlertDescription 112
pattern BadCertificateStatusResponse :: AlertDescription
pattern BadCertificateStatusResponse  = AlertDescription 113
pattern BadCertificateHashValue      :: AlertDescription
pattern BadCertificateHashValue       = AlertDescription 114
pattern UnknownPskIdentity           :: AlertDescription
pattern UnknownPskIdentity            = AlertDescription 115
pattern CertificateRequired          :: AlertDescription
pattern CertificateRequired           = AlertDescription 116
pattern NoApplicationProtocol        :: AlertDescription
pattern NoApplicationProtocol         = AlertDescription 120 -- RFC7301

instance Show AlertDescription where
    show CloseNotify                  = "CloseNotify"
    show UnexpectedMessage            = "UnexpectedMessage"
    show BadRecordMac                 = "BadRecordMac"
    show DecryptionFailed             = "DecryptionFailed"
    show RecordOverflow               = "RecordOverflow"
    show DecompressionFailure         = "DecompressionFailure"
    show HandshakeFailure             = "HandshakeFailure"
    show BadCertificate               = "BadCertificate"
    show UnsupportedCertificate       = "UnsupportedCertificate"
    show CertificateRevoked           = "CertificateRevoked"
    show CertificateExpired           = "CertificateExpired"
    show CertificateUnknown           = "CertificateUnknown"
    show IllegalParameter             = "IllegalParameter"
    show UnknownCa                    = "UnknownCa"
    show AccessDenied                 = "AccessDenied"
    show DecodeError                  = "DecodeError"
    show DecryptError                 = "DecryptError"
    show ExportRestriction            = "ExportRestriction"
    show ProtocolVersion              = "ProtocolVersion"
    show InsufficientSecurity         = "InsufficientSecurity"
    show InternalError                = "InternalError"
    show InappropriateFallback        = "InappropriateFallback"
    show UserCanceled                 = "UserCanceled"
    show NoRenegotiation              = "NoRenegotiation"
    show MissingExtension             = "MissingExtension"
    show UnsupportedExtension         = "UnsupportedExtension"
    show CertificateUnobtainable      = "CertificateUnobtainable"
    show UnrecognizedName             = "UnrecognizedName"
    show BadCertificateStatusResponse = "BadCertificateStatusResponse"
    show BadCertificateHashValue      = "BadCertificateHashValue"
    show UnknownPskIdentity           = "UnknownPskIdentity"
    show CertificateRequired          = "CertificateRequired"
    show NoApplicationProtocol        = "NoApplicationProtocol"
    show (AlertDescription x)         = "AlertDescription " ++ show x
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

newtype HandshakeType = HandshakeType {fromHandshakeType :: Word8}
    deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern HandshakeType_HelloRequest        :: HandshakeType
pattern HandshakeType_HelloRequest         = HandshakeType 0
pattern HandshakeType_ClientHello         :: HandshakeType
pattern HandshakeType_ClientHello          = HandshakeType 1
pattern HandshakeType_ServerHello         :: HandshakeType
pattern HandshakeType_ServerHello          = HandshakeType 2
pattern HandshakeType_NewSessionTicket    :: HandshakeType
pattern HandshakeType_NewSessionTicket     = HandshakeType 4
pattern HandshakeType_EndOfEarlyData      :: HandshakeType
pattern HandshakeType_EndOfEarlyData       = HandshakeType 5
pattern HandshakeType_EncryptedExtensions :: HandshakeType
pattern HandshakeType_EncryptedExtensions  = HandshakeType 8
pattern HandshakeType_Certificate         :: HandshakeType
pattern HandshakeType_Certificate          = HandshakeType 11
pattern HandshakeType_ServerKeyXchg       :: HandshakeType
pattern HandshakeType_ServerKeyXchg        = HandshakeType 12
pattern HandshakeType_CertRequest         :: HandshakeType
pattern HandshakeType_CertRequest          = HandshakeType 13
pattern HandshakeType_ServerHelloDone     :: HandshakeType
pattern HandshakeType_ServerHelloDone      = HandshakeType 14
pattern HandshakeType_CertVerify          :: HandshakeType
pattern HandshakeType_CertVerify           = HandshakeType 15
pattern HandshakeType_ClientKeyXchg       :: HandshakeType
pattern HandshakeType_ClientKeyXchg        = HandshakeType 16
pattern HandshakeType_Finished            :: HandshakeType
pattern HandshakeType_Finished             = HandshakeType 20
pattern HandshakeType_KeyUpdate           :: HandshakeType
pattern HandshakeType_KeyUpdate            = HandshakeType 24

instance Show HandshakeType where
    show HandshakeType_HelloRequest    = "HandshakeType_HelloRequest"
    show HandshakeType_ClientHello     = "HandshakeType_ClientHello"
    show HandshakeType_ServerHello     = "HandshakeType_ServerHello"
    show HandshakeType_Certificate     = "HandshakeType_Certificate"
    show HandshakeType_ServerKeyXchg   = "HandshakeType_ServerKeyXchg"
    show HandshakeType_CertRequest     = "HandshakeType_CertRequest"
    show HandshakeType_ServerHelloDone = "HandshakeType_ServerHelloDone"
    show HandshakeType_CertVerify      = "HandshakeType_CertVerify"
    show HandshakeType_ClientKeyXchg   = "HandshakeType_ClientKeyXchg"
    show HandshakeType_Finished        = "HandshakeType_Finished"
    show (HandshakeType x)             = "HandshakeType " ++ show x
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

newtype BigNum = BigNum ByteString
    deriving (Show, Eq)

bigNumToInteger :: BigNum -> Integer
bigNumToInteger (BigNum b) = os2ip b

bigNumFromInteger :: Integer -> BigNum
bigNumFromInteger i = BigNum $ i2osp i

----------------------------------------------------------------

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

----------------------------------------------------------------

data ServerECDHParams = ServerECDHParams Group GroupPublic
    deriving (Show, Eq)

----------------------------------------------------------------

data ServerRSAParams = ServerRSAParams
    { rsa_modulus :: Integer
    , rsa_exponent :: Integer
    }
    deriving (Show, Eq)

----------------------------------------------------------------

data ServerKeyXchgAlgorithmData
    = SKX_DH_Anon ServerDHParams
    | SKX_DHE_DSA ServerDHParams DigitallySigned
    | SKX_DHE_RSA ServerDHParams DigitallySigned
    | SKX_ECDHE_RSA ServerECDHParams DigitallySigned
    | SKX_ECDHE_ECDSA ServerECDHParams DigitallySigned
    | SKX_RSA (Maybe ServerRSAParams)
    | SKX_DH_DSA (Maybe ServerRSAParams)
    | SKX_DH_RSA (Maybe ServerRSAParams)
    | SKX_Unparsed ByteString -- if we parse the server key xchg before knowing the actual cipher, we end up with this structure.
    | SKX_Unknown ByteString
    deriving (Show, Eq)

----------------------------------------------------------------

data ClientKeyXchgAlgorithmData
    = CKX_RSA ByteString
    | CKX_DH DHPublic
    | CKX_ECDH ByteString
    deriving (Show, Eq)

type DeprecatedRecord = ByteString

----------------------------------------------------------------

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

{- FOURMOLU_DISABLE -}
packetType :: Packet -> ProtocolType
packetType (Handshake _)    = ProtocolType_Handshake
packetType (Alert _)        = ProtocolType_Alert
packetType ChangeCipherSpec = ProtocolType_ChangeCipherSpec
packetType (AppData _)      = ProtocolType_AppData

typeOfHandshake :: Handshake -> HandshakeType
typeOfHandshake ClientHello{}   = HandshakeType_ClientHello
typeOfHandshake ServerHello{}   = HandshakeType_ServerHello
typeOfHandshake Certificates{}  = HandshakeType_Certificate
typeOfHandshake HelloRequest    = HandshakeType_HelloRequest
typeOfHandshake ServerHelloDone = HandshakeType_ServerHelloDone
typeOfHandshake ClientKeyXchg{} = HandshakeType_ClientKeyXchg
typeOfHandshake ServerKeyXchg{} = HandshakeType_ServerKeyXchg
typeOfHandshake CertRequest{}   = HandshakeType_CertRequest
typeOfHandshake CertVerify{}    = HandshakeType_CertVerify
typeOfHandshake Finished{}      = HandshakeType_Finished
{- FOURMOLU_ENABLE -}
