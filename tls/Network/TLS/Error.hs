{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE PatternSynonyms #-}

module Network.TLS.Error where

import Control.Exception (Exception (..))
import Data.Typeable

import Network.TLS.Imports

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
    | Error_TCP_Terminate
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
pattern GeneralError                 :: AlertDescription
pattern GeneralError                  = AlertDescription 117
pattern NoApplicationProtocol        :: AlertDescription
pattern NoApplicationProtocol         = AlertDescription 120 -- RFC7301
pattern EchRequired                  :: AlertDescription
pattern EchRequired                   = AlertDescription 121 -- draft

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
    show GeneralError                 = "GeneralError"
    show NoApplicationProtocol        = "NoApplicationProtocol"
    show EchRequired                  = "EchRequired"
    show (AlertDescription x)         = "AlertDescription " ++ show x
{- FOURMOLU_ENABLE -}
