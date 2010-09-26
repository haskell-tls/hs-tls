-- |
-- Module      : Network.TLS.Struct
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Struct module contains all definitions and values of the TLS protocol
--
module Network.TLS.Struct
	( Bytes
	, Version(..)
	, ConnectionEnd(..)
	, CipherType(..)
	, CipherData(..)
	, Extension
	, EncryptedData(..)
	, CertificateType(..)
	, HashAlgorithm(..)
	, SignatureAlgorithm(..)
	, ProtocolType(..)
	, TLSError(..)
	, ServerDHParams(..)
	, ServerRSAParams(..)
	, ServerKeyXchgAlgorithmData(..)
	, Packet(..)
	, Header(..)
	, ServerRandom(..)
	, ClientRandom(..)
	, ClientKeyData(..)
	, serverRandom
	, clientRandom
	, FinishedData
	, Session(..)
	, AlertLevel(..)
	, AlertDescription(..)
	, HandshakeType(..)
	, Handshake(..)
	, numericalVer
	, verOfNum
	, TypeValuable, valOfType, valToType
	, packetType
	, typeOfHandshake
	) where

import Data.ByteString (ByteString, pack)
import Data.Word
import Data.Certificate.X509

type Bytes = ByteString

data Version = SSL2 | SSL3 | TLS10 | TLS11 | TLS12 deriving (Show, Eq, Ord)

data ConnectionEnd = ConnectionServer | ConnectionClient
data CipherType = CipherStream | CipherBlock | CipherAEAD

data CipherData = CipherData
	{ cipherDataContent :: Bytes
	, cipherDataMAC     :: Maybe Bytes
	, cipherDataPadding :: Maybe Bytes
	} deriving (Show,Eq)

data CertificateType =
	  CertificateType_RSA_Sign         -- TLS10
	| CertificateType_DSS_Sign         -- TLS10
	| CertificateType_RSA_Fixed_DH     -- TLS10
	| CertificateType_DSS_Fixed_DH     -- TLS10
	| CertificateType_RSA_Ephemeral_dh -- TLS12
	| CertificateType_DSS_Ephemeral_dh -- TLS12
	| CertificateType_fortezza_dms     -- TLS12
	| CertificateType_Unknown Word8
	deriving (Show,Eq)

data HashAlgorithm =
	  HashNone
	| HashMD5
	| HashSHA1
	| HashSHA224
	| HashSHA256
	| HashSHA384
	| HashSHA512
	| HashOther Word8
	deriving (Show,Eq)

data SignatureAlgorithm =
	  SignatureAnonymous
	| SignatureRSA
	| SignatureDSS
	| SignatureECDSA
	| SignatureOther Word8
	deriving (Show,Eq)

data ProtocolType =
	  ProtocolType_ChangeCipherSpec
	| ProtocolType_Alert
	| ProtocolType_Handshake
	| ProtocolType_AppData
	deriving (Eq, Show)

data TLSError =
	  Error_Misc String
	| Error_Certificate String
	| Error_Digest ([Word8], [Word8])
	| Error_Packet String
	| Error_Packet_Size_Mismatch (Int, Int)
	| Error_Internal_Packet_Remaining Int
	| Error_Internal_Packet_ByteProcessed Int Int Int
	| Error_Unknown_Version Word8 Word8
	| Error_Unknown_Type String
	deriving (Eq, Show)

data Packet =
	  Handshake Handshake
	| Alert (AlertLevel, AlertDescription)
	| ChangeCipherSpec
	| AppData ByteString
	deriving (Show,Eq)

data Header = Header ProtocolType Version Word16 deriving (Show, Eq)

newtype ServerRandom = ServerRandom Bytes deriving (Show, Eq)
newtype ClientRandom = ClientRandom Bytes deriving (Show, Eq)
newtype ClientKeyData = ClientKeyData Bytes deriving (Show, Eq)
newtype Session = Session (Maybe Bytes) deriving (Show, Eq)
type CipherID = Word16
type CompressionID = Word8
type FinishedData = [Word8]
type Extension = (Word16, [Word8])

constrRandom32 :: (Bytes -> a) -> [Word8] -> Maybe a
constrRandom32 constr l = if length l == 32 then Just (constr $ pack l) else Nothing

serverRandom :: [Word8] -> Maybe ServerRandom
serverRandom l = constrRandom32 ServerRandom l

clientRandom :: [Word8] -> Maybe ClientRandom
clientRandom l = constrRandom32 ClientRandom l

newtype EncryptedData = EncryptedData ByteString
	deriving (Show)

data AlertLevel =
	  AlertLevel_Warning
	| AlertLevel_Fatal
	deriving (Show,Eq)

data AlertDescription =
	  CloseNotify
	| UnexpectedMessage
	| BadRecordMac
	| DecryptionFailed
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
	| UserCanceled
	| NoRenegotiation
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

data ServerDHParams = ServerDHParams
	{ dh_p  :: Integer -- ^ prime modulus
	, dh_g  :: Integer -- ^ generator
	, dh_Ys :: Integer -- ^ public value (g^X mod p)
	} deriving (Show,Eq)

data ServerRSAParams = ServerRSAParams
	{ rsa_modulus  :: Integer
	, rsa_exponent :: Integer
	} deriving (Show,Eq)

data ServerKeyXchgAlgorithmData =
	  SKX_DH_Anon ServerDHParams
	| SKX_DHE_DSS ServerDHParams [Word8]
	| SKX_DHE_RSA ServerDHParams [Word8]
	| SKX_RSA (Maybe ServerRSAParams)
	| SKX_DH_DSS (Maybe ServerRSAParams)
	| SKX_DH_RSA (Maybe ServerRSAParams)
	deriving (Show,Eq)

data Handshake =
	  ClientHello !Version !ClientRandom !Session ![CipherID] ![CompressionID] (Maybe [Extension])
	| ServerHello !Version !ServerRandom !Session !CipherID !CompressionID (Maybe [Extension])
	| Certificates [Certificate]
	| HelloRequest
	| ServerHelloDone
	| ClientKeyXchg Version ClientKeyData
	| ServerKeyXchg ServerKeyXchgAlgorithmData
	| CertRequest [CertificateType] (Maybe [ (HashAlgorithm, SignatureAlgorithm) ]) [Word8]
	| CertVerify [Word8]
	| Finished FinishedData
	deriving (Show,Eq)

packetType :: Packet -> ProtocolType
packetType (Handshake _)    = ProtocolType_Handshake
packetType (Alert _)        = ProtocolType_Alert
packetType ChangeCipherSpec = ProtocolType_ChangeCipherSpec
packetType (AppData _)      = ProtocolType_AppData

typeOfHandshake :: Handshake -> HandshakeType
typeOfHandshake (ClientHello _ _ _ _ _ _) = HandshakeType_ClientHello
typeOfHandshake (ServerHello _ _ _ _ _ _) = HandshakeType_ServerHello
typeOfHandshake (Certificates _)          = HandshakeType_Certificate
typeOfHandshake (HelloRequest)            = HandshakeType_HelloRequest
typeOfHandshake (ServerHelloDone)         = HandshakeType_ServerHelloDone
typeOfHandshake (ClientKeyXchg _ _)       = HandshakeType_ClientKeyXchg
typeOfHandshake (ServerKeyXchg _)         = HandshakeType_ServerKeyXchg
typeOfHandshake (CertRequest _ _ _)       = HandshakeType_CertRequest
typeOfHandshake (CertVerify _)            = HandshakeType_CertVerify
typeOfHandshake (Finished _)              = HandshakeType_Finished

numericalVer :: Version -> (Word8, Word8)
numericalVer SSL2  = (2, 0)
numericalVer SSL3  = (3, 0)
numericalVer TLS10 = (3, 1)
numericalVer TLS11 = (3, 2)
numericalVer TLS12 = (3, 3)

verOfNum :: (Word8, Word8) -> Maybe Version
verOfNum (2, 0) = Just SSL2
verOfNum (3, 0) = Just SSL3
verOfNum (3, 1) = Just TLS10
verOfNum (3, 2) = Just TLS11
verOfNum (3, 3) = Just TLS12
verOfNum _      = Nothing

class TypeValuable a where
	valOfType :: a -> Word8
	valToType :: Word8 -> Maybe a

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
	valOfType ProtocolType_ChangeCipherSpec = 20
	valOfType ProtocolType_Alert            = 21
	valOfType ProtocolType_Handshake        = 22
	valOfType ProtocolType_AppData          = 23

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
	valOfType UserCanceled           = 90
	valOfType NoRenegotiation        = 100

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
	valToType 90  = Just UserCanceled
	valToType 100 = Just NoRenegotiation
	valToType _   = Nothing

instance TypeValuable CertificateType where
	valOfType CertificateType_RSA_Sign         = 1
	valOfType CertificateType_DSS_Sign         = 2
	valOfType CertificateType_RSA_Fixed_DH     = 3
	valOfType CertificateType_DSS_Fixed_DH     = 4
	valOfType CertificateType_RSA_Ephemeral_dh = 5
	valOfType CertificateType_DSS_Ephemeral_dh = 6
	valOfType CertificateType_fortezza_dms     = 20
	valOfType (CertificateType_Unknown i)      = i

	valToType 1  = Just CertificateType_RSA_Sign
	valToType 2  = Just CertificateType_DSS_Sign
	valToType 3  = Just CertificateType_RSA_Fixed_DH
	valToType 4  = Just CertificateType_DSS_Fixed_DH
	valToType 5  = Just CertificateType_RSA_Ephemeral_dh
	valToType 6  = Just CertificateType_DSS_Ephemeral_dh
	valToType 20 = Just CertificateType_fortezza_dms
	valToType i  = Just (CertificateType_Unknown i)

instance TypeValuable HashAlgorithm where
	valOfType HashNone      = 0
	valOfType HashMD5       = 1
	valOfType HashSHA1      = 2
	valOfType HashSHA224    = 3
	valOfType HashSHA256    = 4
	valOfType HashSHA384    = 5
	valOfType HashSHA512    = 6
	valOfType (HashOther i) = i

	valToType 0 = Just HashNone
	valToType 1 = Just HashMD5
	valToType 2 = Just HashSHA1
	valToType 3 = Just HashSHA224
	valToType 4 = Just HashSHA256
	valToType 5 = Just HashSHA384
	valToType 6 = Just HashSHA512
	valToType i = Just (HashOther i)

instance TypeValuable SignatureAlgorithm where
	valOfType SignatureAnonymous = 0
	valOfType SignatureRSA       = 1
	valOfType SignatureDSS       = 2
	valOfType SignatureECDSA     = 3
	valOfType (SignatureOther i) = i

	valToType 0 = Just SignatureAnonymous
	valToType 1 = Just SignatureRSA
	valToType 2 = Just SignatureDSS
	valToType 3 = Just SignatureECDSA
	valToType i = Just (SignatureOther i)
