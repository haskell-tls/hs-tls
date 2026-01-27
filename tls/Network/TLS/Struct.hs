{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# OPTIONS_HADDOCK hide #-}

-- | The Struct module contains all definitions and values of the TLS
-- protocol.
module Network.TLS.Struct (
    Version (..),
    CipherData (..),
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
    VerifyData (..),
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
        HandshakeType_KeyUpdate,
        HandshakeType_CompressedCertificate
    ),
    CertificateChain_ (..),
    emptyCertificateChain_,
    Handshake (..),
    packetType,
    typeOfHandshake,
    module Network.TLS.HashAndSignature,
    ExtensionRaw (..),
    ExtensionID (..),
    showCertificateChain,
    isHelloRetryRequest,
    hrrRandom,
    ClientHello (..),
    ServerHello (..),
    HandshakeR,
) where

import Data.X509 (
    CertificateChain (..),
    DistinguishedName,
    certSubjectDN,
    getCharacterStringRawData,
    getDistinguishedElements,
    getSigned,
    signedObject,
 )

import Network.TLS.Crypto
import Network.TLS.Error
import {-# SOURCE #-} Network.TLS.Extension
import Network.TLS.HashAndSignature
import Network.TLS.Imports
import Network.TLS.Types

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
    show CertificateType_RSA_Sign     = "rsa_sign"
    show CertificateType_DSA_Sign     = "dss_sign"
    show CertificateType_ECDSA_Sign   = "ecdsa_sign"
    show CertificateType_Ed25519_Sign = "ed25519_sign"
    show CertificateType_Ed448_Sign   = "ed448_sign"
    show (CertificateType x)          = "CertificateType " ++ show x
{- FOURMOLU_ENABLE -}

-- | Last supported certificate type, no 'CertificateType that
-- compares greater than this one (based on the 'Ord' instance,
-- not on the wire code point) will be reported to the application
-- via the client certificate request callback.
lastSupportedCertificateType :: CertificateType
lastSupportedCertificateType = CertificateType_ECDSA_Sign

------------------------------------------------------------

type Signature = ByteString

data DigitallySigned = DigitallySigned HashAndSignatureAlgorithm Signature
    deriving (Eq)

instance Show DigitallySigned where
    show (DigitallySigned hs _sig) = "DigitallySigned " ++ show hs ++ " \"...\""

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

data Packet
    = Handshake [Handshake] [WireBytes]
    | Alert [(AlertLevel, AlertDescription)]
    | ChangeCipherSpec
    | AppData ByteString
    deriving (Eq)

instance Show Packet where
    show (Handshake hs _) = "Handshake " ++ show hs
    show (Alert as) = "Alert " ++ show as
    show ChangeCipherSpec = "ChangeCipherSpec"
    show (AppData bs) = "AppData " ++ showBytesHex bs

data Header = Header ProtocolType Version Word16 deriving (Show, Eq)

newtype ServerRandom = ServerRandom {unServerRandom :: ByteString}
    deriving (Eq)
instance Show ServerRandom where
    show sr@(ServerRandom bs)
        | isHelloRetryRequest sr = "HelloRetryReqest"
        | otherwise = "ServerRandom " ++ showBytesHex bs

hrrRandom :: ServerRandom
hrrRandom =
    ServerRandom
        "\xCF\x21\xAD\x74\xE5\x9A\x61\x11\xBE\x1D\x8C\x02\x1E\x65\xB8\x91\xC2\xA2\x11\x16\x7A\xBB\x8C\x5E\x07\x9E\x09\xE2\xC8\xA8\x33\x9C"

isHelloRetryRequest :: ServerRandom -> Bool
isHelloRetryRequest = (== hrrRandom)

newtype ClientRandom = ClientRandom {unClientRandom :: ByteString}
    deriving (Eq)

instance Show ClientRandom where
    show (ClientRandom bs) = "ClientRandom " ++ showBytesHex bs

newtype Session = Session (Maybe SessionID) deriving (Eq)
instance Show Session where
    show (Session Nothing) = "Session \"\""
    show (Session (Just bs)) = "Session " ++ showBytesHex bs

{-# DEPRECATED FinishedData "use VerifyData" #-}
type FinishedData = ByteString

newtype VerifyData = VerifyData ByteString deriving (Eq)
instance Show VerifyData where
    show (VerifyData bs) = showBytesHex bs

----------------------------------------------------------------

newtype HandshakeType = HandshakeType {fromHandshakeType :: Word8}
    deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern HandshakeType_HelloRequest          :: HandshakeType
pattern HandshakeType_HelloRequest           = HandshakeType 0
pattern HandshakeType_ClientHello           :: HandshakeType
pattern HandshakeType_ClientHello            = HandshakeType 1
pattern HandshakeType_ServerHello           :: HandshakeType
pattern HandshakeType_ServerHello            = HandshakeType 2
pattern HandshakeType_NewSessionTicket      :: HandshakeType
pattern HandshakeType_NewSessionTicket       = HandshakeType 4
pattern HandshakeType_EndOfEarlyData        :: HandshakeType
pattern HandshakeType_EndOfEarlyData         = HandshakeType 5
pattern HandshakeType_EncryptedExtensions   :: HandshakeType
pattern HandshakeType_EncryptedExtensions    = HandshakeType 8
pattern HandshakeType_Certificate           :: HandshakeType
pattern HandshakeType_Certificate            = HandshakeType 11
pattern HandshakeType_ServerKeyXchg         :: HandshakeType
pattern HandshakeType_ServerKeyXchg          = HandshakeType 12
pattern HandshakeType_CertRequest           :: HandshakeType
pattern HandshakeType_CertRequest            = HandshakeType 13
pattern HandshakeType_ServerHelloDone       :: HandshakeType
pattern HandshakeType_ServerHelloDone        = HandshakeType 14
pattern HandshakeType_CertVerify            :: HandshakeType
pattern HandshakeType_CertVerify             = HandshakeType 15
pattern HandshakeType_ClientKeyXchg         :: HandshakeType
pattern HandshakeType_ClientKeyXchg          = HandshakeType 16
pattern HandshakeType_Finished              :: HandshakeType
pattern HandshakeType_Finished               = HandshakeType 20
pattern HandshakeType_KeyUpdate             :: HandshakeType
pattern HandshakeType_KeyUpdate              = HandshakeType 24
pattern HandshakeType_CompressedCertificate :: HandshakeType
pattern HandshakeType_CompressedCertificate  = HandshakeType 25

instance Show HandshakeType where
    show HandshakeType_HelloRequest          = "HelloRequest"
    show HandshakeType_ClientHello           = "ClientHello"
    show HandshakeType_ServerHello           = "ServerHello"
    show HandshakeType_NewSessionTicket      = "NewSessionTicket"
    show HandshakeType_EndOfEarlyData        = "EndOfEarlyData"
    show HandshakeType_EncryptedExtensions   = "EncryptedExtensions"
    show HandshakeType_Certificate           = "Certificate"
    show HandshakeType_ServerKeyXchg         = "ServerKeyXchg"
    show HandshakeType_CertRequest           = "CertRequest"
    show HandshakeType_ServerHelloDone       = "ServerHelloDone"
    show HandshakeType_CertVerify            = "CertVerify"
    show HandshakeType_ClientKeyXchg         = "ClientKeyXchg"
    show HandshakeType_Finished              = "Finished"
    show HandshakeType_KeyUpdate             = "KeyUpdate"
    show HandshakeType_CompressedCertificate = "CompressedCertificate"
    show (HandshakeType x)                   = "HandshakeType " ++ show x
{- FOURMOLU_ENABLE -}

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

data ServerDSAParams = ServerDSAParams deriving (Show, Eq)

----------------------------------------------------------------

data ServerKeyXchgAlgorithmData
    = SKX_DH_Anon ServerDHParams
    | SKX_DHE_DSA ServerDHParams DigitallySigned
    | SKX_DHE_RSA ServerDHParams DigitallySigned
    | SKX_ECDHE_RSA ServerECDHParams DigitallySigned
    | SKX_ECDHE_ECDSA ServerECDHParams DigitallySigned
    | SKX_RSA (Maybe ServerRSAParams)
    | SKX_DH_DSA (Maybe ServerDSAParams)
    | SKX_DH_RSA (Maybe ServerRSAParams)
    | SKX_Unparsed ByteString -- if we parse the server key xchg before knowing the actual cipher, we end up with this structure.
    | SKX_Unknown ByteString
    deriving (Eq)

{- FOURMOLU_DISABLE -}
instance Show ServerKeyXchgAlgorithmData where
    show (SKX_DH_Anon _)       = "SKX_DH_Anon"
    show (SKX_DHE_DSA _ _)     = "SKX_DHE_DSA"
    show (SKX_DHE_RSA _ _)     = "SKX_DHE_RSA"
    show (SKX_ECDHE_RSA _ _)   = "SKX_ECDHE_RSA"
    show (SKX_ECDHE_ECDSA _ _) = "SKX_ECDHE_ECDSA"
    show (SKX_RSA _)           = "SKX_RSA"
    show (SKX_DH_DSA _)        = "SKX_DH_DSA"
    show (SKX_DH_RSA _)        = "SKX_DH_RSA"
    show (SKX_Unparsed _)      = "SKX_Unparsed"
    show (SKX_Unknown _)       = "SKX_Unknown"
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

data ClientKeyXchgAlgorithmData
    = CKX_RSA ByteString
    | CKX_DH DHPublic
    | CKX_ECDH ByteString
    deriving (Eq)

instance Show ClientKeyXchgAlgorithmData where
    show (CKX_RSA _bs) = "CKX_RSA \"...\""
    show (CKX_DH pub) = "CKX_DH " ++ show pub
    show (CKX_ECDH _bs) = "CKX_ECDH \"...\""

----------------------------------------------------------------

newtype CertificateChain_ = CertificateChain_ CertificateChain deriving (Eq)
instance Show CertificateChain_ where
    show (CertificateChain_ cc) = showCertificateChain cc

emptyCertificateChain_ :: CertificateChain_
emptyCertificateChain_ = CertificateChain_ (CertificateChain [])

showCertificateChain :: CertificateChain -> String
showCertificateChain (CertificateChain xs) = show $ map getName xs
  where
    getName =
        maybe "" getCharacterStringRawData
            . lookup [2, 5, 4, 3]
            . getDistinguishedElements
            . certSubjectDN
            . signedObject
            . getSigned

data ClientHello = CH
    { chVersion :: Version
    , chRandom :: ClientRandom
    , chSession :: Session
    , chCiphers :: [CipherId]
    , chComps :: [CompressionID]
    , chExtensions :: [ExtensionRaw]
    }
    deriving (Eq, Show)

data ServerHello = SH
    { shVersion :: Version
    , shRandom :: ServerRandom
    , shSession :: Session
    , shCipher :: CipherId
    , shComp :: CompressionID
    , shExtensions :: [ExtensionRaw]
    }
    deriving (Eq, Show)

data Handshake
    = ClientHello ClientHello
    | ServerHello ServerHello
    | Certificate CertificateChain_
    | HelloRequest
    | ServerHelloDone
    | ClientKeyXchg ClientKeyXchgAlgorithmData
    | ServerKeyXchg ServerKeyXchgAlgorithmData
    | CertRequest
        [CertificateType]
        [HashAndSignatureAlgorithm]
        [DistinguishedName]
    | CertVerify DigitallySigned
    | Finished VerifyData
    | NewSessionTicket Second Ticket
    deriving (Show, Eq)

{- FOURMOLU_DISABLE -}
packetType :: Packet -> ProtocolType
packetType (Handshake _ _)  = ProtocolType_Handshake
packetType (Alert _)        = ProtocolType_Alert
packetType ChangeCipherSpec = ProtocolType_ChangeCipherSpec
packetType (AppData _)      = ProtocolType_AppData

typeOfHandshake :: Handshake -> HandshakeType
typeOfHandshake ClientHello{}      = HandshakeType_ClientHello
typeOfHandshake ServerHello{}      = HandshakeType_ServerHello
typeOfHandshake Certificate{}      = HandshakeType_Certificate
typeOfHandshake HelloRequest       = HandshakeType_HelloRequest
typeOfHandshake ServerHelloDone    = HandshakeType_ServerHelloDone
typeOfHandshake ClientKeyXchg{}    = HandshakeType_ClientKeyXchg
typeOfHandshake ServerKeyXchg{}    = HandshakeType_ServerKeyXchg
typeOfHandshake CertRequest{}      = HandshakeType_CertRequest
typeOfHandshake CertVerify{}       = HandshakeType_CertVerify
typeOfHandshake Finished{}         = HandshakeType_Finished
typeOfHandshake NewSessionTicket{} = HandshakeType_NewSessionTicket
{- FOURMOLU_ENABLE -}

type HandshakeR = (Handshake, WireBytes)
