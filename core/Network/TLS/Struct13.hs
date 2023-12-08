-- |
-- Module      : Network.TLS.Struct13
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
module Network.TLS.Struct13 (
    Packet13 (..),
    Handshake13 (..),
    typeOfHandshake13,
    contentType,
    KeyUpdate (..),
) where

import Data.X509 (CertificateChain)
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

type TicketNonce = ByteString

-- fixme: convert Word32 to proper data type
data Handshake13
    = ClientHello13 !Version !ClientRandom !Session ![CipherID] [ExtensionRaw]
    | ServerHello13 !ServerRandom !Session !CipherID [ExtensionRaw]
    | NewSessionTicket13 Second Word32 TicketNonce SessionIDorTicket [ExtensionRaw]
    | EndOfEarlyData13
    | EncryptedExtensions13 [ExtensionRaw]
    | CertRequest13 CertReqContext [ExtensionRaw]
    | Certificate13 CertReqContext CertificateChain [[ExtensionRaw]]
    | CertVerify13 HashAndSignatureAlgorithm Signature
    | Finished13 FinishedData
    | KeyUpdate13 KeyUpdate
    deriving (Show, Eq)

{- FOURMOLU_DISABLE -}
typeOfHandshake13 :: Handshake13 -> HandshakeType
typeOfHandshake13 ClientHello13{}         = HandshakeType_ClientHello
typeOfHandshake13 ServerHello13{}         = HandshakeType_ServerHello
typeOfHandshake13 EndOfEarlyData13{}      = HandshakeType_EndOfEarlyData
typeOfHandshake13 NewSessionTicket13{}    = HandshakeType_NewSessionTicket
typeOfHandshake13 EncryptedExtensions13{} = HandshakeType_EncryptedExtensions
typeOfHandshake13 CertRequest13{}         = HandshakeType_CertRequest
typeOfHandshake13 Certificate13{}         = HandshakeType_Certificate
typeOfHandshake13 CertVerify13{}          = HandshakeType_CertVerify
typeOfHandshake13 Finished13{}            = HandshakeType_Finished
typeOfHandshake13 KeyUpdate13{}           = HandshakeType_KeyUpdate

contentType :: Packet13 -> ProtocolType
contentType ChangeCipherSpec13 = ProtocolType_ChangeCipherSpec
contentType Handshake13{}      = ProtocolType_Handshake
contentType Alert13{}          = ProtocolType_Alert
contentType AppData13{}        = ProtocolType_AppData
{- FOURMOLU_ENABLE -}
