{-# LANGUAGE BangPatterns #-}
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
    , extensionID_ApplicationLayerProtocolNegotiation
    , extensionID_ExtendedMasterSecret
    , extensionID_NegotiatedGroups
    , extensionID_EcPointFormats
    , extensionID_Heartbeat
    , extensionID_SignatureAlgorithms
    , extensionID_PreSharedKey
    , extensionID_EarlyData
    , extensionID_SupportedVersions
    , extensionID_Cookie
    , extensionID_PskKeyExchangeModes
    , extensionID_CertificateAuthorities
    , extensionID_OidFilters
    , extensionID_PostHandshakeAuth
    , extensionID_SignatureAlgorithmsCert
    , extensionID_KeyShare
    , extensionID_QuicTransportParameters
    -- all implemented extensions
    , ServerNameType(..)
    , ServerName(..)
    , MaxFragmentLength(..)
    , MaxFragmentEnum(..)
    , SecureRenegotiation(..)
    , ApplicationLayerProtocolNegotiation(..)
    , ExtendedMasterSecret(..)
    , NegotiatedGroups(..)
    , Group(..)
    , EcPointFormatsSupported(..)
    , EcPointFormat(..)
    , SessionTicket(..)
    , HeartBeat(..)
    , HeartBeatMode(..)
    , SignatureAlgorithms(..)
    , SignatureAlgorithmsCert(..)
    , SupportedVersions(..)
    , KeyShare(..)
    , KeyShareEntry(..)
    , MessageType(..)
    , PostHandshakeAuth(..)
    , PskKexMode(..)
    , PskKeyExchangeModes(..)
    , PskIdentity(..)
    , PreSharedKey(..)
    , EarlyDataIndication(..)
    , Cookie(..)
    , CertificateAuthorities(..)
    ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

import Network.TLS.Struct ( DistinguishedName
                          , ExtensionID
                          , EnumSafe8(..)
                          , EnumSafe16(..)
                          , HashAndSignatureAlgorithm )
import Network.TLS.Crypto.Types
import Network.TLS.Types (Version(..), HostName)

import Network.TLS.Wire
import Network.TLS.Imports
import Network.TLS.Packet ( putDNames
                          , getDNames
                          , putSignatureHashAlgorithm
                          , getSignatureHashAlgorithm
                          , putBinaryVersion
                          , getBinaryVersion
                          )

------------------------------------------------------------

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
  , extensionID_NegotiatedGroups
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
  , extensionID_PreSharedKey
  , extensionID_EarlyData
  , extensionID_SupportedVersions
  , extensionID_Cookie
  , extensionID_PskKeyExchangeModes
  , extensionID_CertificateAuthorities
  , extensionID_OidFilters
  , extensionID_PostHandshakeAuth
  , extensionID_SignatureAlgorithmsCert
  , extensionID_KeyShare
  , extensionID_SecureRenegotiation
  , extensionID_QuicTransportParameters :: ExtensionID
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
extensionID_NegotiatedGroups                    = 0xa -- RFC4492bis and TLS 1.3
extensionID_EcPointFormats                      = 0xb -- RFC4492
extensionID_SRP                                 = 0xc -- RFC5054
extensionID_SignatureAlgorithms                 = 0xd -- RFC5246, TLS 1.3
extensionID_SRTP                                = 0xe -- RFC5764
extensionID_Heartbeat                           = 0xf -- RFC6520
extensionID_ApplicationLayerProtocolNegotiation = 0x10 -- RFC7301
extensionID_StatusRequestv2                     = 0x11 -- RFC6961
extensionID_SignedCertificateTimestamp          = 0x12 -- RFC6962
extensionID_ClientCertificateType               = 0x13 -- RFC7250
extensionID_ServerCertificateType               = 0x14 -- RFC7250
extensionID_Padding                             = 0x15 -- draft-agl-tls-padding. expires 2015-03-12
extensionID_EncryptThenMAC                      = 0x16 -- RFC7366
extensionID_ExtendedMasterSecret                = 0x17 -- REF7627
extensionID_SessionTicket                       = 0x23 -- RFC4507
-- Reserved                                       0x28 -- TLS 1.3
extensionID_PreSharedKey                        = 0x29 -- TLS 1.3
extensionID_EarlyData                           = 0x2a -- TLS 1.3
extensionID_SupportedVersions                   = 0x2b -- TLS 1.3
extensionID_Cookie                              = 0x2c -- TLS 1.3
extensionID_PskKeyExchangeModes                 = 0x2d -- TLS 1.3
-- Reserved                                       0x2e -- TLS 1.3
extensionID_CertificateAuthorities              = 0x2f -- TLS 1.3
extensionID_OidFilters                          = 0x30 -- TLS 1.3
extensionID_PostHandshakeAuth                   = 0x31 -- TLS 1.3
extensionID_SignatureAlgorithmsCert             = 0x32 -- TLS 1.3
extensionID_KeyShare                            = 0x33 -- TLS 1.3
extensionID_SecureRenegotiation                 = 0xff01 -- RFC5746
extensionID_QuicTransportParameters             = 0xffa5

------------------------------------------------------------

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
    , extensionID_NegotiatedGroups
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
    , extensionID_PreSharedKey
    , extensionID_EarlyData
    , extensionID_SupportedVersions
    , extensionID_Cookie
    , extensionID_PskKeyExchangeModes
    , extensionID_KeyShare
    , extensionID_SignatureAlgorithmsCert
    , extensionID_CertificateAuthorities
    , extensionID_SecureRenegotiation
    , extensionID_QuicTransportParameters
    ]

-- | all supported extensions by the implementation
supportedExtensions :: [ExtensionID]
supportedExtensions = [ extensionID_ServerName
                      , extensionID_MaxFragmentLength
                      , extensionID_ApplicationLayerProtocolNegotiation
                      , extensionID_ExtendedMasterSecret
                      , extensionID_SecureRenegotiation
                      , extensionID_NegotiatedGroups
                      , extensionID_EcPointFormats
                      , extensionID_SignatureAlgorithms
                      , extensionID_SignatureAlgorithmsCert
                      , extensionID_KeyShare
                      , extensionID_PreSharedKey
                      , extensionID_EarlyData
                      , extensionID_SupportedVersions
                      , extensionID_Cookie
                      , extensionID_PskKeyExchangeModes
                      , extensionID_CertificateAuthorities
                      , extensionID_QuicTransportParameters
                      ]

------------------------------------------------------------

data MessageType = MsgTClientHello
                 | MsgTServerHello
                 | MsgTHelloRetryRequest
                 | MsgTEncryptedExtensions
                 | MsgTNewSessionTicket
                 | MsgTCertificateRequest
                 deriving (Eq,Show)

-- | Extension class to transform bytes to and from a high level Extension type.
class Extension a where
    extensionID     :: a -> ExtensionID
    extensionDecode :: MessageType -> ByteString -> Maybe a
    extensionEncode :: a -> ByteString

------------------------------------------------------------

-- | Server Name extension including the name type and the associated name.
-- the associated name decoding is dependant of its name type.
-- name type = 0 : hostname
newtype ServerName = ServerName [ServerNameType] deriving (Show,Eq)

data ServerNameType = ServerNameHostName HostName
                    | ServerNameOther    (Word8, ByteString)
                    deriving (Show,Eq)

instance Extension ServerName where
    extensionID _ = extensionID_ServerName
    extensionEncode (ServerName l) = runPut $ putOpaque16 (runPut $ mapM_ encodeNameType l)
        where encodeNameType (ServerNameHostName hn)       = putWord8 0  >> putOpaque16 (BC.pack hn) -- FIXME: should be puny code conversion
              encodeNameType (ServerNameOther (nt,opaque)) = putWord8 nt >> putBytes opaque
    extensionDecode MsgTClientHello = decodeServerName
    extensionDecode MsgTServerHello = decodeServerName
    extensionDecode MsgTEncryptedExtensions = decodeServerName
    extensionDecode _               = error "extensionDecode: ServerName"

decodeServerName :: ByteString -> Maybe ServerName
decodeServerName = runGetMaybe $ do
    len <- fromIntegral <$> getWord16
    ServerName <$> getList len getServerName
  where
    getServerName = do
        ty    <- getWord8
        snameParsed <- getOpaque16
        let !sname = B.copy snameParsed
            name = case ty of
              0 -> ServerNameHostName $ BC.unpack sname -- FIXME: should be puny code conversion
              _ -> ServerNameOther (ty, sname)
        return (1+2+B.length sname, name)

------------------------------------------------------------

-- | Max fragment extension with length from 512 bytes to 4096 bytes
--
-- RFC 6066 defines:
-- If a server receives a maximum fragment length negotiation request
-- for a value other than the allowed values, it MUST abort the
-- handshake with an "illegal_parameter" alert.
--
-- So, if a server receives MaxFragmentLengthOther, it must send the alert.
data MaxFragmentLength = MaxFragmentLength MaxFragmentEnum
                       | MaxFragmentLengthOther Word8
                       deriving (Show,Eq)

data MaxFragmentEnum = MaxFragment512
                     | MaxFragment1024
                     | MaxFragment2048
                     | MaxFragment4096
                     deriving (Show,Eq)

instance Extension MaxFragmentLength where
    extensionID _ = extensionID_MaxFragmentLength
    extensionEncode (MaxFragmentLength l) = runPut $ putWord8 $ fromMaxFragmentEnum l
      where
        fromMaxFragmentEnum MaxFragment512  = 1
        fromMaxFragmentEnum MaxFragment1024 = 2
        fromMaxFragmentEnum MaxFragment2048 = 3
        fromMaxFragmentEnum MaxFragment4096 = 4
    extensionEncode (MaxFragmentLengthOther l) = runPut $ putWord8 l
    extensionDecode MsgTClientHello = decodeMaxFragmentLength
    extensionDecode MsgTServerHello = decodeMaxFragmentLength
    extensionDecode MsgTEncryptedExtensions = decodeMaxFragmentLength
    extensionDecode _               = error "extensionDecode: MaxFragmentLength"

decodeMaxFragmentLength :: ByteString -> Maybe MaxFragmentLength
decodeMaxFragmentLength = runGetMaybe $ toMaxFragmentEnum <$> getWord8
  where
    toMaxFragmentEnum 1 = MaxFragmentLength MaxFragment512
    toMaxFragmentEnum 2 = MaxFragmentLength MaxFragment1024
    toMaxFragmentEnum 3 = MaxFragmentLength MaxFragment2048
    toMaxFragmentEnum 4 = MaxFragmentLength MaxFragment4096
    toMaxFragmentEnum n = MaxFragmentLengthOther n

------------------------------------------------------------

-- | Secure Renegotiation
data SecureRenegotiation = SecureRenegotiation ByteString (Maybe ByteString)
    deriving (Show,Eq)

instance Extension SecureRenegotiation where
    extensionID _ = extensionID_SecureRenegotiation
    extensionEncode (SecureRenegotiation cvd svd) =
        runPut $ putOpaque8 (cvd `B.append` fromMaybe B.empty svd)
    extensionDecode msgtype = runGetMaybe $ do
        opaque <- getOpaque8
        case msgtype of
          MsgTServerHello -> let (cvd, svd) = B.splitAt (B.length opaque `div` 2) opaque
                             in return $ SecureRenegotiation cvd (Just svd)
          MsgTClientHello -> return $ SecureRenegotiation opaque Nothing
          _               -> error "extensionDecode: SecureRenegotiation"

------------------------------------------------------------

-- | Application Layer Protocol Negotiation (ALPN)
newtype ApplicationLayerProtocolNegotiation = ApplicationLayerProtocolNegotiation [ByteString] deriving (Show,Eq)

instance Extension ApplicationLayerProtocolNegotiation where
    extensionID _ = extensionID_ApplicationLayerProtocolNegotiation
    extensionEncode (ApplicationLayerProtocolNegotiation bytes) =
        runPut $ putOpaque16 $ runPut $ mapM_ putOpaque8 bytes
    extensionDecode MsgTClientHello = decodeApplicationLayerProtocolNegotiation
    extensionDecode MsgTServerHello = decodeApplicationLayerProtocolNegotiation
    extensionDecode MsgTEncryptedExtensions = decodeApplicationLayerProtocolNegotiation
    extensionDecode _               = error "extensionDecode: ApplicationLayerProtocolNegotiation"

decodeApplicationLayerProtocolNegotiation :: ByteString -> Maybe ApplicationLayerProtocolNegotiation
decodeApplicationLayerProtocolNegotiation = runGetMaybe $ do
    len <- getWord16
    ApplicationLayerProtocolNegotiation <$> getList (fromIntegral len) getALPN
  where
    getALPN = do
        alpnParsed <- getOpaque8
        let !alpn = B.copy alpnParsed
        return (B.length alpn + 1, alpn)

------------------------------------------------------------

-- | Extended Master Secret
data ExtendedMasterSecret = ExtendedMasterSecret deriving (Show,Eq)

instance Extension ExtendedMasterSecret where
    extensionID _ = extensionID_ExtendedMasterSecret
    extensionEncode ExtendedMasterSecret = B.empty
    extensionDecode MsgTClientHello _ = Just ExtendedMasterSecret
    extensionDecode MsgTServerHello _ = Just ExtendedMasterSecret
    extensionDecode _               _ = error "extensionDecode: ExtendedMasterSecret"

------------------------------------------------------------

newtype NegotiatedGroups = NegotiatedGroups [Group] deriving (Show,Eq)

-- on decode, filter all unknown curves
instance Extension NegotiatedGroups where
    extensionID _ = extensionID_NegotiatedGroups
    extensionEncode (NegotiatedGroups groups) = runPut $ putWords16 $ map fromEnumSafe16 groups
    extensionDecode MsgTClientHello = decodeNegotiatedGroups
    extensionDecode MsgTEncryptedExtensions = decodeNegotiatedGroups
    extensionDecode _               = error "extensionDecode: NegotiatedGroups"

decodeNegotiatedGroups :: ByteString -> Maybe NegotiatedGroups
decodeNegotiatedGroups =
    runGetMaybe (NegotiatedGroups . mapMaybe toEnumSafe16 <$> getWords16)

------------------------------------------------------------

newtype EcPointFormatsSupported = EcPointFormatsSupported [EcPointFormat] deriving (Show,Eq)

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
    extensionDecode MsgTClientHello = decodeEcPointFormatsSupported
    extensionDecode MsgTServerHello = decodeEcPointFormatsSupported
    extensionDecode _ = error "extensionDecode: EcPointFormatsSupported"

decodeEcPointFormatsSupported :: ByteString -> Maybe EcPointFormatsSupported
decodeEcPointFormatsSupported =
    runGetMaybe (EcPointFormatsSupported . mapMaybe toEnumSafe8 <$> getWords8)

------------------------------------------------------------

-- Fixme: this is incomplete
-- newtype SessionTicket = SessionTicket ByteString
data SessionTicket = SessionTicket
    deriving (Show,Eq)

instance Extension SessionTicket where
    extensionID _ = extensionID_SessionTicket
    extensionEncode SessionTicket{} = runPut $ return ()
    extensionDecode MsgTClientHello = runGetMaybe (return SessionTicket)
    extensionDecode MsgTServerHello = runGetMaybe (return SessionTicket)
    extensionDecode _               = error "extensionDecode: SessionTicket"

------------------------------------------------------------

newtype HeartBeat = HeartBeat HeartBeatMode deriving (Show,Eq)

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
    extensionDecode MsgTClientHello = decodeHeartBeat
    extensionDecode MsgTServerHello = decodeHeartBeat
    extensionDecode _               = error "extensionDecode: HeartBeat"

decodeHeartBeat :: ByteString -> Maybe HeartBeat
decodeHeartBeat = runGetMaybe $ do
    mm <- toEnumSafe8 <$> getWord8
    case mm of
      Just m  -> return $ HeartBeat m
      Nothing -> fail "unknown HeartBeatMode"

------------------------------------------------------------

newtype SignatureAlgorithms = SignatureAlgorithms [HashAndSignatureAlgorithm] deriving (Show,Eq)

instance Extension SignatureAlgorithms where
    extensionID _ = extensionID_SignatureAlgorithms
    extensionEncode (SignatureAlgorithms algs) =
        runPut $ putWord16 (fromIntegral (length algs * 2)) >> mapM_ putSignatureHashAlgorithm algs
    extensionDecode MsgTClientHello = decodeSignatureAlgorithms
    extensionDecode MsgTCertificateRequest = decodeSignatureAlgorithms
    extensionDecode _               = error "extensionDecode: SignatureAlgorithms"

decodeSignatureAlgorithms :: ByteString -> Maybe SignatureAlgorithms
decodeSignatureAlgorithms = runGetMaybe $ do
    len <- getWord16
    SignatureAlgorithms <$> getList (fromIntegral len) (getSignatureHashAlgorithm >>= \sh -> return (2, sh))

------------------------------------------------------------

data PostHandshakeAuth = PostHandshakeAuth deriving (Show,Eq)

instance Extension PostHandshakeAuth where
    extensionID _ = extensionID_PostHandshakeAuth
    extensionEncode _               = B.empty
    extensionDecode MsgTClientHello = runGetMaybe $ return PostHandshakeAuth
    extensionDecode _               = error "extensionDecode: PostHandshakeAuth"

------------------------------------------------------------

newtype SignatureAlgorithmsCert = SignatureAlgorithmsCert [HashAndSignatureAlgorithm] deriving (Show,Eq)

instance Extension SignatureAlgorithmsCert where
    extensionID _ = extensionID_SignatureAlgorithmsCert
    extensionEncode (SignatureAlgorithmsCert algs) =
        runPut $ putWord16 (fromIntegral (length algs * 2)) >> mapM_ putSignatureHashAlgorithm algs
    extensionDecode MsgTClientHello = decodeSignatureAlgorithmsCert
    extensionDecode MsgTCertificateRequest = decodeSignatureAlgorithmsCert
    extensionDecode _               = error "extensionDecode: SignatureAlgorithmsCert"

decodeSignatureAlgorithmsCert :: ByteString -> Maybe SignatureAlgorithmsCert
decodeSignatureAlgorithmsCert = runGetMaybe $ do
    len <- getWord16
    SignatureAlgorithmsCert <$> getList (fromIntegral len) (getSignatureHashAlgorithm >>= \sh -> return (2, sh))

------------------------------------------------------------

data SupportedVersions =
    SupportedVersionsClientHello [Version]
  | SupportedVersionsServerHello Version
    deriving (Show,Eq)

instance Extension SupportedVersions where
    extensionID _ = extensionID_SupportedVersions
    extensionEncode (SupportedVersionsClientHello vers) = runPut $ do
        putWord8 (fromIntegral (length vers * 2))
        mapM_ putBinaryVersion vers
    extensionEncode (SupportedVersionsServerHello ver) = runPut $
        putBinaryVersion ver
    extensionDecode MsgTClientHello = runGetMaybe $ do
        len <- fromIntegral <$> getWord8
        SupportedVersionsClientHello . catMaybes <$> getList len getVer
      where
        getVer = do
            ver <- getBinaryVersion
            return (2,ver)
    extensionDecode MsgTServerHello = runGetMaybe $ do
        mver <- getBinaryVersion
        case mver of
          Just ver -> return $ SupportedVersionsServerHello ver
          Nothing  -> fail "extensionDecode: SupportedVersionsServerHello"
    extensionDecode _ = error "extensionDecode: SupportedVersionsServerHello"

------------------------------------------------------------

data KeyShareEntry = KeyShareEntry {
    keyShareEntryGroup :: Group
  , keySHareEntryKeyExchange:: ByteString
  } deriving (Show,Eq)

getKeyShareEntry :: Get (Int, Maybe KeyShareEntry)
getKeyShareEntry = do
    g <- getWord16
    l <- fromIntegral <$> getWord16
    key <- getBytes l
    let !len = l + 4
    case toEnumSafe16 g of
      Nothing  -> return (len, Nothing)
      Just grp -> return (len, Just $ KeyShareEntry grp key)

putKeyShareEntry :: KeyShareEntry -> Put
putKeyShareEntry (KeyShareEntry grp key) = do
    putWord16 $ fromEnumSafe16 grp
    putWord16 $ fromIntegral $ B.length key
    putBytes key

data KeyShare =
    KeyShareClientHello [KeyShareEntry]
  | KeyShareServerHello KeyShareEntry
  | KeyShareHRR Group
    deriving (Show,Eq)

instance Extension KeyShare where
    extensionID _ = extensionID_KeyShare
    extensionEncode (KeyShareClientHello kses) = runPut $ do
        let !len = sum [B.length key + 4 | KeyShareEntry _ key <- kses]
        putWord16 $ fromIntegral len
        mapM_ putKeyShareEntry kses
    extensionEncode (KeyShareServerHello kse) = runPut $ putKeyShareEntry kse
    extensionEncode (KeyShareHRR grp) = runPut $ putWord16 $ fromEnumSafe16 grp
    extensionDecode MsgTServerHello  = runGetMaybe $ do
        (_, ment) <- getKeyShareEntry
        case ment of
            Nothing  -> fail "decoding KeyShare for ServerHello"
            Just ent -> return $ KeyShareServerHello ent
    extensionDecode MsgTClientHello = runGetMaybe $ do
        len <- fromIntegral <$> getWord16
        grps <- getList len getKeyShareEntry
        return $ KeyShareClientHello $ catMaybes grps
    extensionDecode MsgTHelloRetryRequest = runGetMaybe $ do
        mgrp <- toEnumSafe16 <$> getWord16
        case mgrp of
          Nothing  -> fail "decoding KeyShare for HRR"
          Just grp -> return $ KeyShareHRR grp
    extensionDecode _ = error "extensionDecode: KeyShare"

------------------------------------------------------------

data PskKexMode = PSK_KE | PSK_DHE_KE deriving (Eq, Show)

instance EnumSafe8 PskKexMode where
    fromEnumSafe8 PSK_KE     = 0
    fromEnumSafe8 PSK_DHE_KE = 1

    toEnumSafe8 0 = Just PSK_KE
    toEnumSafe8 1 = Just PSK_DHE_KE
    toEnumSafe8 _ = Nothing

newtype PskKeyExchangeModes = PskKeyExchangeModes [PskKexMode] deriving (Eq, Show)

instance Extension PskKeyExchangeModes where
    extensionID _ = extensionID_PskKeyExchangeModes
    extensionEncode (PskKeyExchangeModes pkms) = runPut $
        putWords8 $ map fromEnumSafe8 pkms
    extensionDecode MsgTClientHello = runGetMaybe $
        PskKeyExchangeModes . mapMaybe toEnumSafe8 <$> getWords8
    extensionDecode _ = error "extensionDecode: PskKeyExchangeModes"

------------------------------------------------------------

data PskIdentity = PskIdentity ByteString Word32 deriving (Eq, Show)

data PreSharedKey =
    PreSharedKeyClientHello [PskIdentity] [ByteString]
  | PreSharedKeyServerHello Int
   deriving (Eq, Show)

instance Extension PreSharedKey where
    extensionID _ = extensionID_PreSharedKey
    extensionEncode (PreSharedKeyClientHello ids bds) = runPut $ do
        putOpaque16 $ runPut (mapM_ putIdentity ids)
        putOpaque16 $ runPut (mapM_ putBinder bds)
      where
        putIdentity (PskIdentity bs w) = do
            putOpaque16 bs
            putWord32 w
        putBinder = putOpaque8
    extensionEncode (PreSharedKeyServerHello w16) = runPut $
        putWord16 $ fromIntegral w16
    extensionDecode MsgTServerHello = runGetMaybe $
        PreSharedKeyServerHello . fromIntegral <$> getWord16
    extensionDecode MsgTClientHello = runGetMaybe $ do
        len1 <- fromIntegral <$> getWord16
        identities <- getList len1 getIdentity
        len2 <- fromIntegral <$> getWord16
        binders <- getList len2 getBinder
        return $ PreSharedKeyClientHello identities binders
      where
        getIdentity = do
            identity <- getOpaque16
            age <- getWord32
            let len = 2 + B.length identity + 4
            return (len, PskIdentity identity age)
        getBinder = do
            l <- fromIntegral <$> getWord8
            binder <- getBytes l
            let len = l + 1
            return (len, binder)
    extensionDecode _ = error "extensionDecode: PreShareKey"

------------------------------------------------------------

newtype EarlyDataIndication = EarlyDataIndication (Maybe Word32) deriving (Eq, Show)

instance Extension EarlyDataIndication where
    extensionID _ = extensionID_EarlyData
    extensionEncode (EarlyDataIndication Nothing)   = runPut $ putBytes B.empty
    extensionEncode (EarlyDataIndication (Just w32)) = runPut $ putWord32 w32
    extensionDecode MsgTClientHello         = return $ Just (EarlyDataIndication Nothing)
    extensionDecode MsgTEncryptedExtensions = return $ Just (EarlyDataIndication Nothing)
    extensionDecode MsgTNewSessionTicket    = runGetMaybe $
        EarlyDataIndication . Just <$> getWord32
    extensionDecode _                       = error "extensionDecode: EarlyDataIndication"

------------------------------------------------------------

newtype Cookie = Cookie ByteString deriving (Eq, Show)

instance Extension Cookie where
    extensionID _ = extensionID_Cookie
    extensionEncode (Cookie opaque) = runPut $ putOpaque16 opaque
    extensionDecode MsgTServerHello = runGetMaybe (Cookie <$> getOpaque16)
    extensionDecode _               = error "extensionDecode: Cookie"

------------------------------------------------------------

newtype CertificateAuthorities = CertificateAuthorities [DistinguishedName]
    deriving (Eq, Show)

instance Extension CertificateAuthorities where
    extensionID _ = extensionID_CertificateAuthorities
    extensionEncode (CertificateAuthorities names) = runPut $
        putDNames names
    extensionDecode MsgTClientHello =
       runGetMaybe (CertificateAuthorities <$> getDNames)
    extensionDecode MsgTCertificateRequest =
       runGetMaybe (CertificateAuthorities <$> getDNames)
    extensionDecode _ = error "extensionDecode: CertificateAuthorities"
