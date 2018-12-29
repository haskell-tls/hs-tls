-- |
-- Module      : Network.TLS.Struct13
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Struct13
       ( Packet13(..)
       , Handshake13(..)
       , HandshakeType13(..)
       , typeOfHandshake13
       , ContentType(..)
       , contentType
       , protoToContent
       , KeyUpdate(..)
       ) where

import Data.X509 (CertificateChain)
import Network.TLS.Struct
import Network.TLS.Types
import Network.TLS.Imports

data Packet13 =
      Handshake13 [Handshake13]
    | Alert13 [(AlertLevel, AlertDescription)]
    | ChangeCipherSpec13
    | AppData13 ByteString
    deriving (Show,Eq)

data KeyUpdate = UpdateNotRequested
               | UpdateRequested
               deriving (Show,Eq)

type TicketNonce = ByteString
type CertReqContext = ByteString

-- fixme: convert Word32 to proper data type
data Handshake13 =
      ClientHello13 !Version !ClientRandom !Session ![CipherID] [ExtensionRaw]
    | ServerHello13 !ServerRandom !Session !CipherID [ExtensionRaw]
    | NewSessionTicket13 Second Word32 TicketNonce SessionID [ExtensionRaw]
    | EndOfEarlyData13
    | EncryptedExtensions13 [ExtensionRaw]
    | CertRequest13 CertReqContext [ExtensionRaw]
    | Certificate13 CertReqContext CertificateChain [[ExtensionRaw]]
    | CertVerify13 HashAndSignatureAlgorithm Signature
    | Finished13 FinishedData
    | KeyUpdate13 KeyUpdate
    deriving (Show,Eq)

data HandshakeType13 =
      HandshakeType_ClientHello13
    | HandshakeType_ServerHello13
    | HandshakeType_EndOfEarlyData13
    | HandshakeType_NewSessionTicket13
    | HandshakeType_EncryptedExtensions13
    | HandshakeType_CertRequest13
    | HandshakeType_Certificate13
    | HandshakeType_CertVerify13
    | HandshakeType_Finished13
    | HandshakeType_KeyUpdate13
    deriving (Show,Eq)

typeOfHandshake13 :: Handshake13 -> HandshakeType13
typeOfHandshake13 ClientHello13{}         = HandshakeType_ClientHello13
typeOfHandshake13 ServerHello13{}         = HandshakeType_ServerHello13
typeOfHandshake13 EndOfEarlyData13{}      = HandshakeType_EndOfEarlyData13
typeOfHandshake13 NewSessionTicket13{}    = HandshakeType_NewSessionTicket13
typeOfHandshake13 EncryptedExtensions13{} = HandshakeType_EncryptedExtensions13
typeOfHandshake13 CertRequest13{}         = HandshakeType_CertRequest13
typeOfHandshake13 Certificate13{}         = HandshakeType_Certificate13
typeOfHandshake13 CertVerify13{}          = HandshakeType_CertVerify13
typeOfHandshake13 Finished13{}            = HandshakeType_Finished13
typeOfHandshake13 KeyUpdate13{}           = HandshakeType_KeyUpdate13

instance TypeValuable HandshakeType13 where
  valOfType HandshakeType_ClientHello13         = 1
  valOfType HandshakeType_ServerHello13         = 2
  valOfType HandshakeType_NewSessionTicket13    = 4
  valOfType HandshakeType_EndOfEarlyData13      = 5
  valOfType HandshakeType_EncryptedExtensions13 = 8
  valOfType HandshakeType_CertRequest13         = 13
  valOfType HandshakeType_Certificate13         = 11
  valOfType HandshakeType_CertVerify13          = 15
  valOfType HandshakeType_Finished13            = 20
  valOfType HandshakeType_KeyUpdate13           = 24

  valToType 1  = Just HandshakeType_ClientHello13
  valToType 2  = Just HandshakeType_ServerHello13
  valToType 4  = Just HandshakeType_NewSessionTicket13
  valToType 5  = Just HandshakeType_EndOfEarlyData13
  valToType 8  = Just HandshakeType_EncryptedExtensions13
  valToType 13 = Just HandshakeType_CertRequest13
  valToType 11 = Just HandshakeType_Certificate13
  valToType 15 = Just HandshakeType_CertVerify13
  valToType 20 = Just HandshakeType_Finished13
  valToType 24 = Just HandshakeType_KeyUpdate13
  valToType _  = Nothing

data ContentType =
      ContentType_ChangeCipherSpec
    | ContentType_Alert
    | ContentType_Handshake
    | ContentType_AppData
    deriving (Eq, Show)


instance TypeValuable ContentType where
    valOfType ContentType_ChangeCipherSpec    = 20
    valOfType ContentType_Alert               = 21
    valOfType ContentType_Handshake           = 22
    valOfType ContentType_AppData             = 23

    valToType 20 = Just ContentType_ChangeCipherSpec
    valToType 21 = Just ContentType_Alert
    valToType 22 = Just ContentType_Handshake
    valToType 23 = Just ContentType_AppData
    valToType _  = Nothing

contentType :: Packet13 -> ContentType
contentType ChangeCipherSpec13 = ContentType_ChangeCipherSpec
contentType (Handshake13 _)    = ContentType_Handshake
contentType (Alert13 _)        = ContentType_Alert
contentType (AppData13 _)      = ContentType_AppData

protoToContent :: ProtocolType -> ContentType
protoToContent ProtocolType_ChangeCipherSpec = ContentType_ChangeCipherSpec
protoToContent ProtocolType_Alert            = ContentType_Alert
protoToContent ProtocolType_Handshake        = ContentType_Handshake
protoToContent ProtocolType_AppData          = ContentType_AppData
protoToContent _                             = error "protoToContent"
