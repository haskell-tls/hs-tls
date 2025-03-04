module Network.TLS.Struct13 (
    Packet13 (..),
    Handshake13 (..),
    typeOfHandshake13,
    contentType,
    KeyUpdate (..),
    CertReqContext,
    isKeyUpdate13,
    TicketNonce (..),
) where

import Network.TLS.Imports
import Network.TLS.Struct
import Network.TLS.Types

data Packet13
    = Handshake13 [Handshake13]
    | Alert13 [(AlertLevel, AlertDescription)]
    | ChangeCipherSpec13
    | AppData13 ByteString
    deriving (Show, Eq)

data KeyUpdate
    = UpdateNotRequested
    | UpdateRequested
    deriving (Show, Eq)

newtype TicketNonce = TicketNonce ByteString deriving (Eq)

instance Show TicketNonce where
    show (TicketNonce bs) = showBytesHex bs

-- fixme: convert Word32 to proper data type
data Handshake13
    = ServerHello13 ServerRandom Session CipherId [ExtensionRaw]
    | NewSessionTicket13 Second Word32 TicketNonce SessionIDorTicket [ExtensionRaw]
    | EndOfEarlyData13
    | EncryptedExtensions13 [ExtensionRaw]
    | Certificate13 CertReqContext TLSCertificateChain [[ExtensionRaw]]
    | CertRequest13 CertReqContext [ExtensionRaw]
    | CertVerify13 DigitallySigned
    | Finished13 VerifyData
    | KeyUpdate13 KeyUpdate
    | CompressedCertificate13 CertReqContext TLSCertificateChain [[ExtensionRaw]]
    deriving (Show, Eq)

-- | Certificate request context for TLS 1.3.
type CertReqContext = ByteString

{- FOURMOLU_DISABLE -}
typeOfHandshake13 :: Handshake13 -> HandshakeType
typeOfHandshake13 ServerHello13{}           = HandshakeType_ServerHello
typeOfHandshake13 NewSessionTicket13{}      = HandshakeType_NewSessionTicket
typeOfHandshake13 EndOfEarlyData13{}        = HandshakeType_EndOfEarlyData
typeOfHandshake13 EncryptedExtensions13{}   = HandshakeType_EncryptedExtensions
typeOfHandshake13 Certificate13{}           = HandshakeType_Certificate
typeOfHandshake13 CertRequest13{}           = HandshakeType_CertRequest
typeOfHandshake13 CertVerify13{}            = HandshakeType_CertVerify
typeOfHandshake13 Finished13{}              = HandshakeType_Finished
typeOfHandshake13 KeyUpdate13{}             = HandshakeType_KeyUpdate
typeOfHandshake13 CompressedCertificate13{} = HandshakeType_CompressedCertificate

contentType :: Packet13 -> ProtocolType
contentType ChangeCipherSpec13 = ProtocolType_ChangeCipherSpec
contentType Handshake13{}      = ProtocolType_Handshake
contentType Alert13{}          = ProtocolType_Alert
contentType AppData13{}        = ProtocolType_AppData
{- FOURMOLU_ENABLE -}

isKeyUpdate13 :: Handshake13 -> Bool
isKeyUpdate13 (KeyUpdate13 _) = True
isKeyUpdate13 _ = False
