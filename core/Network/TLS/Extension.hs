-- |
-- Module      : Network.TLS.Extension
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- basic extensions are defined in RFC 6066
--
module Network.TLS.Extension
    ( Extension(..)
    , supportedExtensions
    , definedExtensions
    -- all extensions ID supported
    , extensionID_ServerName
    , extensionID_MaxFragmentLength
    , extensionID_SecureRenegotiation
    , extensionID_NextProtocolNegotiation
    , extensionID_ApplicationLayerProtocolNegotiation
    , extensionID_Groups
    , extensionID_EcPointFormats
    , extensionID_Heartbeat
    , extensionID_SignatureAlgorithms
    -- all implemented extensions
    , ServerNameType(..)
    , ServerName(..)
    , MaxFragmentLength(..)
    , MaxFragmentEnum(..)
    , SecureRenegotiation(..)
    , NextProtocolNegotiation(..)
    , ApplicationLayerProtocolNegotiation(..)
    , NegotiatedGroups(..)
    , Group(..)
    , EcPointFormatsSupported(..)
    , EcPointFormat(..)
    , SessionTicket(..)
    , HeartBeat(..)
    , HeartBeatMode(..)
    , SignatureAlgorithms(..)
    ) where

import Control.Monad

import Data.Word
import Data.Maybe (fromMaybe, catMaybes)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

import Network.TLS.Struct (ExtensionID, EnumSafe8(..), EnumSafe16(..), HashAndSignatureAlgorithm)
import Network.TLS.Crypto.Types
import Network.TLS.Wire
import Network.TLS.Imports
import Network.TLS.Packet (putSignatureHashAlgorithm, getSignatureHashAlgorithm)

type HostName = String

-- central list defined in <http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.txt>
extensionID_ServerName
  , extensionID_MaxFragmentLength
  , extensionID_ClientCertificateUrl
  , extensionID_TrustedCAKeys
  , extensionID_TruncatedHMAC
  , extensionID_StatusRequest
  , extensionID_UserMapping
  , extensionID_ClientAuthz
  , extensionID_ServerAuthz
  , extensionID_CertType
  , extensionID_Groups
  , extensionID_EcPointFormats
  , extensionID_SRP
  , extensionID_SignatureAlgorithms
  , extensionID_SRTP
  , extensionID_Heartbeat
  , extensionID_ApplicationLayerProtocolNegotiation
  , extensionID_StatusRequestv2
  , extensionID_SignedCertificateTimestamp
  , extensionID_ClientCertificateType
  , extensionID_ServerCertificateType
  , extensionID_Padding
  , extensionID_EncryptThenMAC
  , extensionID_ExtendedMasterSecret
  , extensionID_SessionTicket
  , extensionID_NextProtocolNegotiation
  , extensionID_SecureRenegotiation :: ExtensionID
extensionID_ServerName                          = 0x0 -- RFC6066
extensionID_MaxFragmentLength                   = 0x1 -- RFC6066
extensionID_ClientCertificateUrl                = 0x2 -- RFC6066
extensionID_TrustedCAKeys                       = 0x3 -- RFC6066
extensionID_TruncatedHMAC                       = 0x4 -- RFC6066
extensionID_StatusRequest                       = 0x5 -- RFC6066
extensionID_UserMapping                         = 0x6 -- RFC4681
extensionID_ClientAuthz                         = 0x7 -- RFC5878
extensionID_ServerAuthz                         = 0x8 -- RFC5878
extensionID_CertType                            = 0x9 -- RFC6091
extensionID_Groups                              = 0xa -- RFC4492bis and TLS 1.3
extensionID_EcPointFormats                      = 0xb -- RFC4492
extensionID_SRP                                 = 0xc -- RFC5054
extensionID_SignatureAlgorithms                 = 0xd -- RFC5246
extensionID_SRTP                                = 0xe -- RFC5764
extensionID_Heartbeat                           = 0xf -- RFC6520
extensionID_ApplicationLayerProtocolNegotiation = 0x10 -- RFC7301
extensionID_StatusRequestv2                     = 0x11 -- RFC6961
extensionID_SignedCertificateTimestamp          = 0x12 -- RFC6962
extensionID_ClientCertificateType               = 0x13 -- RFC7250
extensionID_ServerCertificateType               = 0x14 -- RFC7250
extensionID_Padding                             = 0x15 -- draft-agl-tls-padding. expires 2015-03-12
extensionID_EncryptThenMAC                      = 0x16 -- RFC7366
extensionID_ExtendedMasterSecret                = 0x17 -- draft-ietf-tls-session-hash. expires 2015-09-26
extensionID_SessionTicket                       = 0x23 -- RFC4507
extensionID_NextProtocolNegotiation             = 0x3374 -- obsolete
extensionID_SecureRenegotiation                 = 0xff01 -- RFC5746

definedExtensions :: [ExtensionID]
definedExtensions =
    [ extensionID_ServerName
    , extensionID_MaxFragmentLength
    , extensionID_ClientCertificateUrl
    , extensionID_TrustedCAKeys
    , extensionID_TruncatedHMAC
    , extensionID_StatusRequest
    , extensionID_UserMapping
    , extensionID_ClientAuthz
    , extensionID_ServerAuthz
    , extensionID_CertType
    , extensionID_Groups
    , extensionID_EcPointFormats
    , extensionID_SRP
    , extensionID_SignatureAlgorithms
    , extensionID_SRTP
    , extensionID_Heartbeat
    , extensionID_ApplicationLayerProtocolNegotiation
    , extensionID_StatusRequestv2
    , extensionID_SignedCertificateTimestamp
    , extensionID_ClientCertificateType
    , extensionID_ServerCertificateType
    , extensionID_Padding
    , extensionID_EncryptThenMAC
    , extensionID_ExtendedMasterSecret
    , extensionID_SessionTicket
    , extensionID_NextProtocolNegotiation
    , extensionID_SecureRenegotiation
    ]

-- | all supported extensions by the implementation
supportedExtensions :: [ExtensionID]
supportedExtensions = [ extensionID_ServerName
                      , extensionID_MaxFragmentLength
                      , extensionID_ApplicationLayerProtocolNegotiation
                      , extensionID_SecureRenegotiation
                      , extensionID_NextProtocolNegotiation
                      , extensionID_Groups
                      , extensionID_EcPointFormats
                      , extensionID_SignatureAlgorithms
                      ]

-- | Extension class to transform bytes to and from a high level Extension type.
class Extension a where
    extensionID     :: a -> ExtensionID
    extensionDecode :: Bool -> ByteString -> Maybe a
    extensionEncode :: a -> ByteString

-- | Server Name extension including the name type and the associated name.
-- the associated name decoding is dependant of its name type.
-- name type = 0 : hostname
data ServerName = ServerName [ServerNameType]
    deriving (Show,Eq)

data ServerNameType = ServerNameHostName HostName
                    | ServerNameOther    (Word8, ByteString)
                    deriving (Show,Eq)

instance Extension ServerName where
    extensionID _ = extensionID_ServerName
    extensionEncode (ServerName l) = runPut $ putOpaque16 (runPut $ mapM_ encodeNameType l)
        where encodeNameType (ServerNameHostName hn)       = putWord8 0  >> putOpaque16 (BC.pack hn) -- FIXME: should be puny code conversion
              encodeNameType (ServerNameOther (nt,opaque)) = putWord8 nt >> putBytes opaque
    extensionDecode _ = runGetMaybe (getWord16 >>= \len -> getList (fromIntegral len) getServerName >>= return . ServerName)
        where getServerName = do
                  ty    <- getWord8
                  sname <- getOpaque16
                  return (1+2+B.length sname, case ty of
                      0 -> ServerNameHostName $ BC.unpack sname -- FIXME: should be puny code conversion
                      _ -> ServerNameOther (ty, sname))

-- | Max fragment extension with length from 512 bytes to 4096 bytes
data MaxFragmentLength = MaxFragmentLength MaxFragmentEnum
    deriving (Show,Eq)
data MaxFragmentEnum = MaxFragment512 | MaxFragment1024 | MaxFragment2048 | MaxFragment4096
    deriving (Show,Eq)

instance Extension MaxFragmentLength where
    extensionID _ = extensionID_MaxFragmentLength
    extensionEncode (MaxFragmentLength e) = B.singleton $ marshallSize e
        where marshallSize MaxFragment512  = 1
              marshallSize MaxFragment1024 = 2
              marshallSize MaxFragment2048 = 3
              marshallSize MaxFragment4096 = 4
    extensionDecode _ = runGetMaybe (MaxFragmentLength . unmarshallSize <$> getWord8)
        where unmarshallSize 1 = MaxFragment512
              unmarshallSize 2 = MaxFragment1024
              unmarshallSize 3 = MaxFragment2048
              unmarshallSize 4 = MaxFragment4096
              unmarshallSize n = error ("unknown max fragment size " ++ show n)

-- | Secure Renegotiation
data SecureRenegotiation = SecureRenegotiation ByteString (Maybe ByteString)
    deriving (Show,Eq)

instance Extension SecureRenegotiation where
    extensionID _ = extensionID_SecureRenegotiation
    extensionEncode (SecureRenegotiation cvd svd) =
        runPut $ putOpaque8 (cvd `B.append` fromMaybe B.empty svd)
    extensionDecode isServerHello = runGetMaybe $ do
        opaque <- getOpaque8
        if isServerHello
           then let (cvd, svd) = B.splitAt (B.length opaque `div` 2) opaque
                 in return $ SecureRenegotiation cvd (Just svd)
           else return $ SecureRenegotiation opaque Nothing

-- | Next Protocol Negotiation
data NextProtocolNegotiation = NextProtocolNegotiation [ByteString]
    deriving (Show,Eq)

instance Extension NextProtocolNegotiation where
    extensionID _ = extensionID_NextProtocolNegotiation
    extensionEncode (NextProtocolNegotiation bytes) =
        runPut $ mapM_ putOpaque8 bytes
    extensionDecode _ = runGetMaybe (NextProtocolNegotiation <$> getNPN)
        where getNPN = do
                 avail <- remaining
                 case avail of
                     0 -> return []
                     _ -> do liftM2 (:) getOpaque8 getNPN

-- | Application Layer Protocol Negotiation (ALPN)
data ApplicationLayerProtocolNegotiation = ApplicationLayerProtocolNegotiation [ByteString]
    deriving (Show,Eq)

instance Extension ApplicationLayerProtocolNegotiation where
    extensionID _ = extensionID_ApplicationLayerProtocolNegotiation
    extensionEncode (ApplicationLayerProtocolNegotiation bytes) =
        runPut $ putOpaque16 $ runPut $ mapM_ putOpaque8 bytes
    extensionDecode _ = runGetMaybe (ApplicationLayerProtocolNegotiation <$> getALPN)
        where getALPN = do
                 _ <- getWord16
                 getALPN'
              getALPN' = do
                 avail <- remaining
                 case avail of
                     0 -> return []
                     _ -> (:) <$> getOpaque8 <*> getALPN'


data NegotiatedGroups = NegotiatedGroups [Group]
    deriving (Show,Eq)

-- on decode, filter all unknown curves
instance Extension NegotiatedGroups where
    extensionID _ = extensionID_Groups
    extensionEncode (NegotiatedGroups groups) = runPut $ putWords16 $ map fromGroup groups
    extensionDecode _ = runGetMaybe (NegotiatedGroups . catMaybes . map toGroup <$> getWords16)

data EcPointFormatsSupported = EcPointFormatsSupported [EcPointFormat]
    deriving (Show,Eq)

data EcPointFormat =
      EcPointFormat_Uncompressed
    | EcPointFormat_AnsiX962_compressed_prime
    | EcPointFormat_AnsiX962_compressed_char2
    deriving (Show,Eq)

instance EnumSafe8 EcPointFormat where
    fromEnumSafe8 EcPointFormat_Uncompressed = 0
    fromEnumSafe8 EcPointFormat_AnsiX962_compressed_prime = 1
    fromEnumSafe8 EcPointFormat_AnsiX962_compressed_char2 = 2

    toEnumSafe8 0 = Just EcPointFormat_Uncompressed
    toEnumSafe8 1 = Just EcPointFormat_AnsiX962_compressed_prime
    toEnumSafe8 2 = Just EcPointFormat_AnsiX962_compressed_char2
    toEnumSafe8 _ = Nothing

-- on decode, filter all unknown formats
instance Extension EcPointFormatsSupported where
    extensionID _ = extensionID_EcPointFormats
    extensionEncode (EcPointFormatsSupported formats) = runPut $ putWords8 $ map fromEnumSafe8 formats
    extensionDecode _ = runGetMaybe (EcPointFormatsSupported . catMaybes . map toEnumSafe8 <$> getWords8)

data SessionTicket = SessionTicket
    deriving (Show,Eq)

instance Extension SessionTicket where
    extensionID _ = extensionID_SessionTicket
    extensionEncode (SessionTicket {}) = runPut $ return ()
    extensionDecode _ = runGetMaybe (return SessionTicket)

data HeartBeat = HeartBeat HeartBeatMode
    deriving (Show,Eq)

data HeartBeatMode =
      HeartBeat_PeerAllowedToSend
    | HeartBeat_PeerNotAllowedToSend
    deriving (Show,Eq)

instance EnumSafe8 HeartBeatMode where
    fromEnumSafe8 HeartBeat_PeerAllowedToSend    = 1
    fromEnumSafe8 HeartBeat_PeerNotAllowedToSend = 2

    toEnumSafe8 1 = Just HeartBeat_PeerAllowedToSend
    toEnumSafe8 2 = Just HeartBeat_PeerNotAllowedToSend
    toEnumSafe8 _ = Nothing

instance Extension HeartBeat where
    extensionID _ = extensionID_Heartbeat
    extensionEncode (HeartBeat mode) = runPut $ putWord8 $ fromEnumSafe8 mode
    extensionDecode _ bs =
        case runGetMaybe (toEnumSafe8 <$> getWord8) bs of
            Just (Just mode) -> Just $ HeartBeat mode
            _                -> Nothing

data SignatureAlgorithms = SignatureAlgorithms [HashAndSignatureAlgorithm]
    deriving (Show,Eq)

instance Extension SignatureAlgorithms where
    extensionID _ = extensionID_SignatureAlgorithms
    extensionEncode (SignatureAlgorithms algs) =
        runPut $ putWord16 (fromIntegral (length algs * 2)) >> mapM_ putSignatureHashAlgorithm algs
    extensionDecode _ =
        runGetMaybe $ do
            len <- getWord16
            SignatureAlgorithms <$> getList (fromIntegral len) (getSignatureHashAlgorithm >>= \sh -> return (2, sh))
