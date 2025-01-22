{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

-- | Basic extensions are defined in RFC 6066
module Network.TLS.Extension (
    -- * Extension identifiers
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
        EID_ExtendedMainSecret,
        EID_CompressCertificate,
        EID_RecordSizeLimit,
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
    definedExtensions,
    supportedExtensions,

    -- * Extension raw
    ExtensionRaw (..),
    toExtensionRaw,
    extensionLookup,
    lookupAndDecode,
    lookupAndDecodeAndDo,

    -- * Class
    Extension (..),

    -- * Extensions
    ServerNameType (..),
    ServerName (..),
    MaxFragmentLength (..),
    MaxFragmentEnum (..),
    SecureRenegotiation (..),
    ApplicationLayerProtocolNegotiation (..),
    ExtendedMainSecret (..),
    CertificateCompressionAlgorithm (.., CCA_Zlib, CCA_Brotli, CCA_Zstd),
    CompressCertificate (..),
    SupportedGroups (..),
    Group (..),
    EcPointFormatsSupported (..),
    EcPointFormat (
        EcPointFormat,
        EcPointFormat_Uncompressed,
        EcPointFormat_AnsiX962_compressed_prime,
        EcPointFormat_AnsiX962_compressed_char2
    ),
    RecordSizeLimit (..),
    SessionTicket (..),
    HeartBeat (..),
    HeartBeatMode (
        HeartBeatMode,
        HeartBeat_PeerAllowedToSend,
        HeartBeat_PeerNotAllowedToSend
    ),
    SignatureAlgorithms (..),
    SignatureAlgorithmsCert (..),
    SupportedVersions (..),
    KeyShare (..),
    KeyShareEntry (..),
    MessageType (..),
    PostHandshakeAuth (..),
    PskKexMode (PskKexMode, PSK_KE, PSK_DHE_KE),
    PskKeyExchangeModes (..),
    PskIdentity (..),
    PreSharedKey (..),
    EarlyDataIndication (..),
    Cookie (..),
    CertificateAuthorities (..),
) where

import qualified Control.Exception as E
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.X509 (DistinguishedName)

import Network.TLS.Crypto.Types
import Network.TLS.Error
import Network.TLS.HashAndSignature
import Network.TLS.Imports
import Network.TLS.Packet (
    getBinaryVersion,
    getDNames,
    getSignatureHashAlgorithm,
    putBinaryVersion,
    putDNames,
    putSignatureHashAlgorithm,
 )
import Network.TLS.Types (HostName, Ticket, Version)
import Network.TLS.Wire

----------------------------------------------------------------
-- Extension identifiers

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
pattern EID_ExtendedMainSecret                  :: ExtensionID -- REF7627
pattern EID_ExtendedMainSecret                   = ExtensionID 0x17
pattern EID_CompressCertificate                 :: ExtensionID -- RFC8879
pattern EID_CompressCertificate                  = ExtensionID 0x1b
pattern EID_RecordSizeLimit                     :: ExtensionID -- RFC8449
pattern EID_RecordSizeLimit                      = ExtensionID 0x1c
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
    show EID_ExtendedMainSecret      = "ExtendedMainSecret"
    show EID_CompressCertificate     = "CompressCertificate"
    show EID_RecordSizeLimit         = "RecordSizeLimit"
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
    show (ExtensionID x)             = "ExtensionID " ++ show x
{- FOURMOLU_ENABLE -}

------------------------------------------------------------

definedExtensions :: [ExtensionID]
definedExtensions =
    [ EID_ServerName
    , EID_MaxFragmentLength
    , EID_ClientCertificateUrl
    , EID_TrustedCAKeys
    , EID_TruncatedHMAC
    , EID_StatusRequest
    , EID_UserMapping
    , EID_ClientAuthz
    , EID_ServerAuthz
    , EID_CertType
    , EID_SupportedGroups
    , EID_EcPointFormats
    , EID_SRP
    , EID_SignatureAlgorithms
    , EID_SRTP
    , EID_Heartbeat
    , EID_ApplicationLayerProtocolNegotiation
    , EID_StatusRequestv2
    , EID_SignedCertificateTimestamp
    , EID_ClientCertificateType
    , EID_ServerCertificateType
    , EID_Padding
    , EID_EncryptThenMAC
    , EID_ExtendedMainSecret
    , EID_CompressCertificate
    , EID_RecordSizeLimit
    , EID_SessionTicket
    , EID_PreSharedKey
    , EID_EarlyData
    , EID_SupportedVersions
    , EID_Cookie
    , EID_PskKeyExchangeModes
    , EID_CertificateAuthorities
    , EID_OidFilters
    , EID_PostHandshakeAuth
    , EID_SignatureAlgorithmsCert
    , EID_KeyShare
    , EID_QuicTransportParameters
    , EID_SecureRenegotiation
    ]

-- | all supported extensions by the implementation
{- FOURMOLU_DISABLE -}
supportedExtensions :: [ExtensionID]
supportedExtensions =
    [ EID_ServerName                          -- 0x00
    , EID_SupportedGroups                     -- 0x0a
    , EID_EcPointFormats                      -- 0x0b
    , EID_SignatureAlgorithms                 -- 0x0d
    , EID_ApplicationLayerProtocolNegotiation -- 0x10
    , EID_ExtendedMainSecret                  -- 0x17
    , EID_CompressCertificate                 -- 0x1b
    , EID_RecordSizeLimit                     -- 0x1c
    , EID_SessionTicket                       -- 0x23
    , EID_PreSharedKey                        -- 0x29
    , EID_EarlyData                           -- 0x2a
    , EID_SupportedVersions                   -- 0x2b
    , EID_Cookie                              -- 0x2c
    , EID_PskKeyExchangeModes                 -- 0x2d
    , EID_CertificateAuthorities              -- 0x2f
    , EID_PostHandshakeAuth                   -- 0x31
    , EID_SignatureAlgorithmsCert             -- 0x32
    , EID_KeyShare                            -- 0x33
    , EID_QuicTransportParameters             -- 0x39
    , EID_SecureRenegotiation                 -- 0xff01
    ]
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

-- | The raw content of a TLS extension.
data ExtensionRaw = ExtensionRaw ExtensionID ByteString
    deriving (Eq)

instance Show ExtensionRaw where
    show (ExtensionRaw eid@EID_ServerName bs) = showExtensionRaw eid bs decodeServerName
    show (ExtensionRaw eid@EID_MaxFragmentLength bs) = showExtensionRaw eid bs decodeMaxFragmentLength
    show (ExtensionRaw eid@EID_SupportedGroups bs) = showExtensionRaw eid bs decodeSupportedGroups
    show (ExtensionRaw eid@EID_EcPointFormats bs) = showExtensionRaw eid bs decodeEcPointFormatsSupported
    show (ExtensionRaw eid@EID_SignatureAlgorithms bs) = showExtensionRaw eid bs decodeSignatureAlgorithms
    show (ExtensionRaw eid@EID_Heartbeat bs) = showExtensionRaw eid bs decodeHeartBeat
    show (ExtensionRaw eid@EID_ApplicationLayerProtocolNegotiation bs) = showExtensionRaw eid bs decodeApplicationLayerProtocolNegotiation
    show (ExtensionRaw eid@EID_ExtendedMainSecret _) = show eid
    show (ExtensionRaw eid@EID_CompressCertificate bs) = showExtensionRaw eid bs decodeCompressCertificate
    show (ExtensionRaw eid@EID_RecordSizeLimit bs) = showExtensionRaw eid bs decodeRecordSizeLimit
    show (ExtensionRaw eid@EID_SessionTicket bs) = showExtensionRaw eid bs decodeSessionTicket
    show (ExtensionRaw eid@EID_PreSharedKey bs) = show eid ++ " " ++ showBytesHex bs
    show (ExtensionRaw eid@EID_EarlyData _) = show eid
    show (ExtensionRaw eid@EID_SupportedVersions bs) = showExtensionRaw eid bs decodeSupportedVersions
    show (ExtensionRaw eid@EID_Cookie bs) = show eid ++ " " ++ showBytesHex bs
    show (ExtensionRaw eid@EID_PskKeyExchangeModes bs) = showExtensionRaw eid bs decodePskKeyExchangeModes
    show (ExtensionRaw eid@EID_CertificateAuthorities bs) = showExtensionRaw eid bs decodeCertificateAuthorities
    show (ExtensionRaw eid@EID_PostHandshakeAuth _) = show eid
    show (ExtensionRaw eid@EID_SignatureAlgorithmsCert bs) = showExtensionRaw eid bs decodeSignatureAlgorithmsCert
    show (ExtensionRaw eid@EID_KeyShare bs) = showExtensionRaw eid bs decodeKeyShare
    show (ExtensionRaw eid@EID_SecureRenegotiation bs) = show eid ++ " " ++ showBytesHex bs
    show (ExtensionRaw eid bs) = "ExtensionRaw " ++ show eid ++ " " ++ showBytesHex bs

showExtensionRaw
    :: Show a => ExtensionID -> ByteString -> (ByteString -> Maybe a) -> String
showExtensionRaw eid bs decode = case decode bs of
    Nothing -> show eid ++ " broken"
    Just x -> show x

toExtensionRaw :: Extension e => e -> ExtensionRaw
toExtensionRaw ext = ExtensionRaw (extensionID ext) (extensionEncode ext)

extensionLookup :: ExtensionID -> [ExtensionRaw] -> Maybe ByteString
extensionLookup toFind exts = extract <$> find idEq exts
  where
    extract (ExtensionRaw _ content) = content
    idEq (ExtensionRaw eid _) = eid == toFind

lookupAndDecode
    :: Extension e
    => ExtensionID
    -> MessageType
    -> [ExtensionRaw]
    -> a
    -> (e -> a)
    -> a
lookupAndDecode eid msgtyp exts defval conv = case extensionLookup eid exts of
    Nothing -> defval
    Just bs -> case extensionDecode msgtyp bs of
        Nothing ->
            E.throw $
                Uncontextualized $
                    Error_Protocol ("Illegal " ++ show eid) DecodeError
        Just val -> conv val

lookupAndDecodeAndDo
    :: Extension a
    => ExtensionID
    -> MessageType
    -> [ExtensionRaw]
    -> IO b
    -> (a -> IO b)
    -> IO b
lookupAndDecodeAndDo eid msgtyp exts defAction action = case extensionLookup eid exts of
    Nothing -> defAction
    Just bs -> case extensionDecode msgtyp bs of
        Nothing ->
            E.throwIO $
                Uncontextualized $
                    Error_Protocol ("Illegal " ++ show eid) DecodeError
        Just val -> action val

------------------------------------------------------------

-- | Extension class to transform bytes to and from a high level Extension type.
class Extension a where
    extensionID :: a -> ExtensionID
    extensionDecode :: MessageType -> ByteString -> Maybe a
    extensionEncode :: a -> ByteString

data MessageType
    = MsgTClientHello
    | MsgTServerHello
    | MsgTHelloRetryRequest
    | MsgTEncryptedExtensions
    | MsgTNewSessionTicket
    | MsgTCertificateRequest
    deriving (Eq, Show)

------------------------------------------------------------

-- | Server Name extension including the name type and the associated name.
-- the associated name decoding is dependant of its name type.
-- name type = 0 : hostname
newtype ServerName = ServerName [ServerNameType] deriving (Show, Eq)

data ServerNameType
    = ServerNameHostName HostName
    | ServerNameOther (Word8, ByteString)
    deriving (Eq)

instance Show ServerNameType where
    show (ServerNameHostName host) = "\"" ++ host ++ "\""
    show (ServerNameOther (w, _)) = "(" ++ show w ++ ", )"

instance Extension ServerName where
    extensionID _ = EID_ServerName

    -- dirty hack for servers
    extensionEncode (ServerName []) = ""
    -- for clients
    extensionEncode (ServerName l) = runPut $ putOpaque16 (runPut $ mapM_ encodeNameType l)
      where
        encodeNameType (ServerNameHostName hn) = putWord8 0 >> putOpaque16 (BC.pack hn) -- FIXME: should be puny code conversion
        encodeNameType (ServerNameOther (nt, opaque)) = putWord8 nt >> putBytes opaque
    extensionDecode MsgTClientHello = decodeServerName
    extensionDecode MsgTServerHello = decodeServerName
    extensionDecode MsgTEncryptedExtensions = decodeServerName
    extensionDecode _ = error "extensionDecode: ServerName"

decodeServerName :: ByteString -> Maybe ServerName
decodeServerName "" = Just $ ServerName [] -- dirty hack for servers
decodeServerName bs = runGetMaybe decode bs
  where
    decode = do
        len <- fromIntegral <$> getWord16
        ServerName <$> getList len getServerName
    getServerName = do
        ty <- getWord8
        snameParsed <- getOpaque16
        let sname = B.copy snameParsed
            name = case ty of
                0 -> ServerNameHostName $ BC.unpack sname -- FIXME: should be puny code conversion
                _ -> ServerNameOther (ty, sname)
        return (1 + 2 + B.length sname, name)

------------------------------------------------------------

-- | Max fragment extension with length from 512 bytes to 4096 bytes
--
-- RFC 6066 defines:
-- If a server receives a maximum fragment length negotiation request
-- for a value other than the allowed values, it MUST abort the
-- handshake with an "illegal_parameter" alert.
--
-- So, if a server receives MaxFragmentLengthOther, it must send the alert.
data MaxFragmentLength
    = MaxFragmentLength MaxFragmentEnum
    | MaxFragmentLengthOther Word8
    deriving (Show, Eq)

data MaxFragmentEnum
    = MaxFragment512
    | MaxFragment1024
    | MaxFragment2048
    | MaxFragment4096
    deriving (Show, Eq)

instance Extension MaxFragmentLength where
    extensionID _ = EID_MaxFragmentLength
    extensionEncode (MaxFragmentLength l) = runPut $ putWord8 $ fromMaxFragmentEnum l
      where
        fromMaxFragmentEnum MaxFragment512 = 1
        fromMaxFragmentEnum MaxFragment1024 = 2
        fromMaxFragmentEnum MaxFragment2048 = 3
        fromMaxFragmentEnum MaxFragment4096 = 4
    extensionEncode (MaxFragmentLengthOther l) = runPut $ putWord8 l
    extensionDecode MsgTClientHello = decodeMaxFragmentLength
    extensionDecode MsgTServerHello = decodeMaxFragmentLength
    extensionDecode MsgTEncryptedExtensions = decodeMaxFragmentLength
    extensionDecode _ = error "extensionDecode: MaxFragmentLength"

decodeMaxFragmentLength :: ByteString -> Maybe MaxFragmentLength
decodeMaxFragmentLength = runGetMaybe $ toMaxFragmentEnum <$> getWord8
  where
    toMaxFragmentEnum 1 = MaxFragmentLength MaxFragment512
    toMaxFragmentEnum 2 = MaxFragmentLength MaxFragment1024
    toMaxFragmentEnum 3 = MaxFragmentLength MaxFragment2048
    toMaxFragmentEnum 4 = MaxFragmentLength MaxFragment4096
    toMaxFragmentEnum n = MaxFragmentLengthOther n

------------------------------------------------------------

newtype SupportedGroups = SupportedGroups [Group] deriving (Show, Eq)

-- on decode, filter all unknown curves
instance Extension SupportedGroups where
    extensionID _ = EID_SupportedGroups
    extensionEncode (SupportedGroups groups) = runPut $ putWords16 $ map (\(Group g) -> g) groups
    extensionDecode MsgTClientHello = decodeSupportedGroups
    extensionDecode MsgTEncryptedExtensions = decodeSupportedGroups
    extensionDecode _ = error "extensionDecode: SupportedGroups"

decodeSupportedGroups :: ByteString -> Maybe SupportedGroups
decodeSupportedGroups =
    runGetMaybe (SupportedGroups . map Group <$> getWords16)

------------------------------------------------------------

newtype EcPointFormatsSupported = EcPointFormatsSupported [EcPointFormat]
    deriving (Show, Eq)

newtype EcPointFormat = EcPointFormat {fromEcPointFormat :: Word8}
    deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern EcPointFormat_Uncompressed              :: EcPointFormat
pattern EcPointFormat_Uncompressed               = EcPointFormat 0
pattern EcPointFormat_AnsiX962_compressed_prime :: EcPointFormat
pattern EcPointFormat_AnsiX962_compressed_prime  = EcPointFormat 1
pattern EcPointFormat_AnsiX962_compressed_char2 :: EcPointFormat
pattern EcPointFormat_AnsiX962_compressed_char2  = EcPointFormat 2

instance Show EcPointFormat where
    show EcPointFormat_Uncompressed = "EcPointFormat_Uncompressed"
    show EcPointFormat_AnsiX962_compressed_prime = "EcPointFormat_AnsiX962_compressed_prime"
    show EcPointFormat_AnsiX962_compressed_char2 = "EcPointFormat_AnsiX962_compressed_char2"
    show (EcPointFormat x) = "EcPointFormat " ++ show x
{- FOURMOLU_ENABLE -}

-- on decode, filter all unknown formats
instance Extension EcPointFormatsSupported where
    extensionID _ = EID_EcPointFormats
    extensionEncode (EcPointFormatsSupported formats) = runPut $ putWords8 $ map fromEcPointFormat formats
    extensionDecode MsgTClientHello = decodeEcPointFormatsSupported
    extensionDecode MsgTServerHello = decodeEcPointFormatsSupported
    extensionDecode _ = error "extensionDecode: EcPointFormatsSupported"

decodeEcPointFormatsSupported :: ByteString -> Maybe EcPointFormatsSupported
decodeEcPointFormatsSupported =
    runGetMaybe (EcPointFormatsSupported . map EcPointFormat <$> getWords8)

------------------------------------------------------------

newtype SignatureAlgorithms = SignatureAlgorithms [HashAndSignatureAlgorithm]
    deriving (Show, Eq)

instance Extension SignatureAlgorithms where
    extensionID _ = EID_SignatureAlgorithms
    extensionEncode (SignatureAlgorithms algs) =
        runPut $
            putWord16 (fromIntegral (length algs * 2))
                >> mapM_ putSignatureHashAlgorithm algs
    extensionDecode MsgTClientHello = decodeSignatureAlgorithms
    extensionDecode MsgTCertificateRequest = decodeSignatureAlgorithms
    extensionDecode _ = error "extensionDecode: SignatureAlgorithms"

decodeSignatureAlgorithms :: ByteString -> Maybe SignatureAlgorithms
decodeSignatureAlgorithms = runGetMaybe $ do
    len <- getWord16
    sas <-
        getList (fromIntegral len) (getSignatureHashAlgorithm >>= \sh -> return (2, sh))
    leftoverLen <- remaining
    when (leftoverLen /= 0) $ fail "decodeSignatureAlgorithms: broken length"
    when (null sas) $ fail "signature algorithms are empty"
    return $ SignatureAlgorithms sas

------------------------------------------------------------

newtype HeartBeat = HeartBeat HeartBeatMode deriving (Show, Eq)

newtype HeartBeatMode = HeartBeatMode {fromHeartBeatMode :: Word8}
    deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern HeartBeat_PeerAllowedToSend    :: HeartBeatMode
pattern HeartBeat_PeerAllowedToSend     = HeartBeatMode 1
pattern HeartBeat_PeerNotAllowedToSend :: HeartBeatMode
pattern HeartBeat_PeerNotAllowedToSend  = HeartBeatMode 2

instance Show HeartBeatMode where
    show HeartBeat_PeerAllowedToSend    = "HeartBeat_PeerAllowedToSend"
    show HeartBeat_PeerNotAllowedToSend = "HeartBeat_PeerNotAllowedToSend"
    show (HeartBeatMode x)              = "HeartBeatMode " ++ show x
{- FOURMOLU_ENABLE -}

instance Extension HeartBeat where
    extensionID _ = EID_Heartbeat
    extensionEncode (HeartBeat mode) = runPut $ putWord8 $ fromHeartBeatMode mode
    extensionDecode MsgTClientHello = decodeHeartBeat
    extensionDecode MsgTServerHello = decodeHeartBeat
    extensionDecode _ = error "extensionDecode: HeartBeat"

decodeHeartBeat :: ByteString -> Maybe HeartBeat
decodeHeartBeat = runGetMaybe $ HeartBeat . HeartBeatMode <$> getWord8

------------------------------------------------------------

-- | Application Layer Protocol Negotiation (ALPN)
newtype ApplicationLayerProtocolNegotiation
    = ApplicationLayerProtocolNegotiation [ByteString]
    deriving (Show, Eq)

instance Extension ApplicationLayerProtocolNegotiation where
    extensionID _ = EID_ApplicationLayerProtocolNegotiation
    extensionEncode (ApplicationLayerProtocolNegotiation bytes) =
        runPut $ putOpaque16 $ runPut $ mapM_ putOpaque8 bytes
    extensionDecode MsgTClientHello = decodeApplicationLayerProtocolNegotiation
    extensionDecode MsgTServerHello = decodeApplicationLayerProtocolNegotiation
    extensionDecode MsgTEncryptedExtensions = decodeApplicationLayerProtocolNegotiation
    extensionDecode _ = error "extensionDecode: ApplicationLayerProtocolNegotiation"

decodeApplicationLayerProtocolNegotiation
    :: ByteString -> Maybe ApplicationLayerProtocolNegotiation
decodeApplicationLayerProtocolNegotiation = runGetMaybe $ do
    len <- getWord16
    ApplicationLayerProtocolNegotiation <$> getList (fromIntegral len) getALPN
  where
    getALPN = do
        alpnParsed <- getOpaque8
        let alpn = B.copy alpnParsed
        return (B.length alpn + 1, alpn)

------------------------------------------------------------

-- | Extended Main Secret
data ExtendedMainSecret = ExtendedMainSecret deriving (Show, Eq)

instance Extension ExtendedMainSecret where
    extensionID _ = EID_ExtendedMainSecret
    extensionEncode ExtendedMainSecret = B.empty
    extensionDecode MsgTClientHello "" = Just ExtendedMainSecret
    extensionDecode MsgTServerHello "" = Just ExtendedMainSecret
    extensionDecode _ _ = error "extensionDecode: ExtendedMainSecret"

------------------------------------------------------------

newtype CertificateCompressionAlgorithm
    = CertificateCompressionAlgorithm Word16
    deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern CCA_Zlib   :: CertificateCompressionAlgorithm
pattern CCA_Zlib    = CertificateCompressionAlgorithm 1
pattern CCA_Brotli :: CertificateCompressionAlgorithm
pattern CCA_Brotli  = CertificateCompressionAlgorithm 2
pattern CCA_Zstd   :: CertificateCompressionAlgorithm
pattern CCA_Zstd    = CertificateCompressionAlgorithm 3

instance Show CertificateCompressionAlgorithm where
    show CCA_Zlib   = "zlib"
    show CCA_Brotli = "brotli"
    show CCA_Zstd   = "zstd"
    show (CertificateCompressionAlgorithm n) = "CertificateCompressionAlgorithm " ++ show n
{- FOURMOLU_ENABLE -}

data CompressCertificate = CompressCertificate [CertificateCompressionAlgorithm]
    deriving (Show, Eq)

instance Extension CompressCertificate where
    extensionID _ = EID_CompressCertificate
    extensionEncode (CompressCertificate cs) = runPut $ do
        putWord8 $ fromIntegral (length cs * 2)
        mapM_ putCCA cs
      where
        putCCA (CertificateCompressionAlgorithm n) = putWord16 n
    extensionDecode _ = decodeCompressCertificate

decodeCompressCertificate :: ByteString -> Maybe CompressCertificate
decodeCompressCertificate = runGetMaybe $ do
    len <- fromIntegral <$> getWord8
    cs <- getList len getCCA
    when (null cs) $ fail "empty list of CertificateCompressionAlgorithm"
    leftoverLen <- remaining
    when (leftoverLen /= 0) $ fail "decodeCompressCertificate: broken length"
    return $ CompressCertificate cs
  where
    getCCA = do
        cca <- CertificateCompressionAlgorithm <$> getWord16
        return (2, cca)

------------------------------------------------------------

newtype RecordSizeLimit = RecordSizeLimit Word16 deriving (Eq, Show)

instance Extension RecordSizeLimit where
    extensionID _ = EID_RecordSizeLimit
    extensionEncode (RecordSizeLimit n) = runPut $ putWord16 n
    extensionDecode _ = decodeRecordSizeLimit

decodeRecordSizeLimit :: ByteString -> Maybe RecordSizeLimit
decodeRecordSizeLimit = runGetMaybe $ do
    r <- RecordSizeLimit <$> getWord16
    leftoverLen <- remaining
    when (leftoverLen /= 0) $ fail "decodeRecordSizeLimit: broken length"
    return r

------------------------------------------------------------

newtype SessionTicket = SessionTicket Ticket
    deriving (Show, Eq)

-- https://datatracker.ietf.org/doc/html/rfc5077#appendix-A
instance Extension SessionTicket where
    extensionID _ = EID_SessionTicket
    extensionEncode (SessionTicket ticket) = runPut $ putBytes ticket
    extensionDecode MsgTClientHello = decodeSessionTicket
    extensionDecode MsgTServerHello = decodeSessionTicket
    extensionDecode _ = error "extensionDecode: SessionTicket"

decodeSessionTicket :: ByteString -> Maybe SessionTicket
decodeSessionTicket = runGetMaybe $ SessionTicket <$> (remaining >>= getBytes)

------------------------------------------------------------

data PskIdentity = PskIdentity ByteString Word32 deriving (Eq, Show)

data PreSharedKey
    = PreSharedKeyClientHello [PskIdentity] [ByteString]
    | PreSharedKeyServerHello Int
    deriving (Eq, Show)

instance Extension PreSharedKey where
    extensionID _ = EID_PreSharedKey
    extensionEncode (PreSharedKeyClientHello ids bds) = runPut $ do
        putOpaque16 $ runPut (mapM_ putIdentity ids)
        putOpaque16 $ runPut (mapM_ putBinder bds)
      where
        putIdentity (PskIdentity bs w) = do
            putOpaque16 bs
            putWord32 w
        putBinder = putOpaque8
    extensionEncode (PreSharedKeyServerHello w16) =
        runPut $
            putWord16 $
                fromIntegral w16
    extensionDecode MsgTServerHello =
        runGetMaybe $
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

newtype EarlyDataIndication = EarlyDataIndication (Maybe Word32)
    deriving (Eq, Show)

instance Extension EarlyDataIndication where
    extensionID _ = EID_EarlyData
    extensionEncode (EarlyDataIndication Nothing) = runPut $ putBytes B.empty
    extensionEncode (EarlyDataIndication (Just w32)) = runPut $ putWord32 w32
    extensionDecode MsgTClientHello = return $ Just (EarlyDataIndication Nothing)
    extensionDecode MsgTEncryptedExtensions = return $ Just (EarlyDataIndication Nothing)
    extensionDecode MsgTNewSessionTicket =
        runGetMaybe $
            EarlyDataIndication . Just <$> getWord32
    extensionDecode _ = error "extensionDecode: EarlyDataIndication"

------------------------------------------------------------

data SupportedVersions
    = SupportedVersionsClientHello [Version]
    | SupportedVersionsServerHello Version
    deriving (Eq)

instance Show SupportedVersions where
    show (SupportedVersionsClientHello vers) = "Versions " ++ show vers
    show (SupportedVersionsServerHello ver) = "Versions " ++ show ver

instance Extension SupportedVersions where
    extensionID _ = EID_SupportedVersions
    extensionEncode (SupportedVersionsClientHello vers) = runPut $ do
        putWord8 (fromIntegral (length vers * 2))
        mapM_ putBinaryVersion vers
    extensionEncode (SupportedVersionsServerHello ver) =
        runPut $
            putBinaryVersion ver
    extensionDecode MsgTClientHello = decodeSupportedVersionsClientHello
    extensionDecode MsgTServerHello = decodeSupportedVersionsServerHello
    extensionDecode _ = error "extensionDecode: SupportedVersionsServerHello"

decodeSupportedVersionsClientHello :: ByteString -> Maybe SupportedVersions
decodeSupportedVersionsClientHello = runGetMaybe $ do
    len <- fromIntegral <$> getWord8
    SupportedVersionsClientHello <$> getList len getVer
  where
    getVer = do
        ver <- getBinaryVersion
        return (2, ver)

decodeSupportedVersionsServerHello :: ByteString -> Maybe SupportedVersions
decodeSupportedVersionsServerHello =
    runGetMaybe (SupportedVersionsServerHello <$> getBinaryVersion)

decodeSupportedVersions :: ByteString -> Maybe SupportedVersions
decodeSupportedVersions bs =
    decodeSupportedVersionsClientHello bs
        <|> decodeSupportedVersionsServerHello bs

------------------------------------------------------------

newtype Cookie = Cookie ByteString deriving (Eq, Show)

instance Extension Cookie where
    extensionID _ = EID_Cookie
    extensionEncode (Cookie opaque) = runPut $ putOpaque16 opaque
    extensionDecode MsgTServerHello = runGetMaybe (Cookie <$> getOpaque16)
    extensionDecode _ = error "extensionDecode: Cookie"

------------------------------------------------------------

newtype PskKexMode = PskKexMode {fromPskKexMode :: Word8} deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern PSK_KE     :: PskKexMode
pattern PSK_KE      = PskKexMode 0
pattern PSK_DHE_KE :: PskKexMode
pattern PSK_DHE_KE  = PskKexMode 1

instance Show PskKexMode where
    show PSK_KE     = "PSK_KE"
    show PSK_DHE_KE = "PSK_DHE_KE"
    show (PskKexMode x) = "PskKexMode " ++ show x
{- FOURMOLU_ENABLE -}

newtype PskKeyExchangeModes = PskKeyExchangeModes [PskKexMode]
    deriving (Eq, Show)

instance Extension PskKeyExchangeModes where
    extensionID _ = EID_PskKeyExchangeModes
    extensionEncode (PskKeyExchangeModes pkms) =
        runPut $
            putWords8 $
                map fromPskKexMode pkms
    extensionDecode MsgTClientHello = decodePskKeyExchangeModes
    extensionDecode _ = error "extensionDecode: PskKeyExchangeModes"

decodePskKeyExchangeModes :: ByteString -> Maybe PskKeyExchangeModes
decodePskKeyExchangeModes =
    runGetMaybe $
        PskKeyExchangeModes . map PskKexMode <$> getWords8

------------------------------------------------------------

newtype CertificateAuthorities = CertificateAuthorities [DistinguishedName]
    deriving (Eq, Show)

instance Extension CertificateAuthorities where
    extensionID _ = EID_CertificateAuthorities
    extensionEncode (CertificateAuthorities names) =
        runPut $
            putDNames names
    extensionDecode MsgTClientHello = decodeCertificateAuthorities
    extensionDecode MsgTCertificateRequest = decodeCertificateAuthorities
    extensionDecode _ = error "extensionDecode: CertificateAuthorities"

decodeCertificateAuthorities :: ByteString -> Maybe CertificateAuthorities
decodeCertificateAuthorities =
    runGetMaybe (CertificateAuthorities <$> getDNames)

------------------------------------------------------------

data PostHandshakeAuth = PostHandshakeAuth deriving (Show, Eq)

instance Extension PostHandshakeAuth where
    extensionID _ = EID_PostHandshakeAuth
    extensionEncode _ = B.empty
    extensionDecode MsgTClientHello = runGetMaybe $ return PostHandshakeAuth
    extensionDecode _ = error "extensionDecode: PostHandshakeAuth"

------------------------------------------------------------

newtype SignatureAlgorithmsCert = SignatureAlgorithmsCert [HashAndSignatureAlgorithm]
    deriving (Show, Eq)

instance Extension SignatureAlgorithmsCert where
    extensionID _ = EID_SignatureAlgorithmsCert
    extensionEncode (SignatureAlgorithmsCert algs) =
        runPut $
            putWord16 (fromIntegral (length algs * 2))
                >> mapM_ putSignatureHashAlgorithm algs
    extensionDecode MsgTClientHello = decodeSignatureAlgorithmsCert
    extensionDecode MsgTCertificateRequest = decodeSignatureAlgorithmsCert
    extensionDecode _ = error "extensionDecode: SignatureAlgorithmsCert"

decodeSignatureAlgorithmsCert :: ByteString -> Maybe SignatureAlgorithmsCert
decodeSignatureAlgorithmsCert = runGetMaybe $ do
    len <- getWord16
    SignatureAlgorithmsCert
        <$> getList (fromIntegral len) (getSignatureHashAlgorithm >>= \sh -> return (2, sh))

------------------------------------------------------------

data KeyShareEntry = KeyShareEntry
    { keyShareEntryGroup :: Group
    , keyShareEntryKeyExchange :: ByteString
    }
    deriving (Eq)

instance Show KeyShareEntry where
    show kse = show $ keyShareEntryGroup kse

getKeyShareEntry :: Get (Int, Maybe KeyShareEntry)
getKeyShareEntry = do
    grp <- Group <$> getWord16
    l <- fromIntegral <$> getWord16
    key <- getBytes l
    let len = l + 4
    return (len, Just $ KeyShareEntry grp key)

putKeyShareEntry :: KeyShareEntry -> Put
putKeyShareEntry (KeyShareEntry (Group grp) key) = do
    putWord16 grp
    putWord16 $ fromIntegral $ B.length key
    putBytes key

data KeyShare
    = KeyShareClientHello [KeyShareEntry]
    | KeyShareServerHello KeyShareEntry
    | KeyShareHRR Group
    deriving (Eq)

{- FOURMOLU_DISABLE -}
instance Show KeyShare where
    show (KeyShareClientHello kses) = "KeyShare " ++ show kses
    show (KeyShareServerHello kse)  = "KeyShare " ++ show kse
    show (KeyShareHRR g)            = "KeyShare " ++ show g
{- FOURMOLU_ENABLE -}

instance Extension KeyShare where
    extensionID _ = EID_KeyShare
    extensionEncode (KeyShareClientHello kses) = runPut $ do
        let len = sum [B.length key + 4 | KeyShareEntry _ key <- kses]
        putWord16 $ fromIntegral len
        mapM_ putKeyShareEntry kses
    extensionEncode (KeyShareServerHello kse) = runPut $ putKeyShareEntry kse
    extensionEncode (KeyShareHRR (Group grp)) = runPut $ putWord16 grp
    extensionDecode MsgTClientHello = decodeKeyShareClientHello
    extensionDecode MsgTServerHello = decodeKeyShareServerHello
    extensionDecode MsgTHelloRetryRequest = decodeKeyShareHRR
    extensionDecode _ = error "extensionDecode: KeyShare"

decodeKeyShareClientHello :: ByteString -> Maybe KeyShare
decodeKeyShareClientHello = runGetMaybe $ do
    len <- fromIntegral <$> getWord16
    --      len == 0 allows for HRR
    grps <- getList len getKeyShareEntry
    return $ KeyShareClientHello $ catMaybes grps

decodeKeyShareServerHello :: ByteString -> Maybe KeyShare
decodeKeyShareServerHello = runGetMaybe $ do
    (_, ment) <- getKeyShareEntry
    case ment of
        Nothing -> fail "decoding KeyShare for ServerHello"
        Just ent -> return $ KeyShareServerHello ent

decodeKeyShareHRR :: ByteString -> Maybe KeyShare
decodeKeyShareHRR =
    runGetMaybe $
        KeyShareHRR . Group <$> getWord16

decodeKeyShare :: ByteString -> Maybe KeyShare
decodeKeyShare bs =
    decodeKeyShareClientHello bs
        <|> decodeKeyShareServerHello bs
        <|> decodeKeyShareHRR bs

------------------------------------------------------------

-- | Secure Renegotiation
data SecureRenegotiation = SecureRenegotiation ByteString ByteString
    deriving (Show, Eq)

instance Extension SecureRenegotiation where
    extensionID _ = EID_SecureRenegotiation
    extensionEncode (SecureRenegotiation cvd svd) =
        runPut $ putOpaque8 (cvd `B.append` svd)
    extensionDecode MsgTClientHello = runGetMaybe $ do
        opaque <- getOpaque8
        return $ SecureRenegotiation opaque ""
    extensionDecode MsgTServerHello = runGetMaybe $ do
        opaque <- getOpaque8
        let (cvd, svd) = B.splitAt (B.length opaque `div` 2) opaque
        return $ SecureRenegotiation cvd svd
    extensionDecode _ = error "extensionDecode: SecureRenegotiation"
