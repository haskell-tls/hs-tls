{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE PatternSynonyms #-}

-- |
-- Module      : Network.TLS.Extension
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- basic extensions are defined in RFC 6066
module Network.TLS.Extension (
    Extension (..),
    supportedExtensions,
    definedExtensions,
    -- all implemented extensions
    ServerNameType (..),
    ServerName (..),
    MaxFragmentLength (..),
    MaxFragmentEnum (..),
    SecureRenegotiation (..),
    ApplicationLayerProtocolNegotiation (..),
    ExtendedMasterSecret (..),
    SupportedGroups (..),
    Group (..),
    EcPointFormatsSupported (..),
    EcPointFormat (
        EcPointFormat,
        EcPointFormat_Uncompressed,
        EcPointFormat_AnsiX962_compressed_prime,
        EcPointFormat_AnsiX962_compressed_char2
    ),
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

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

import Network.TLS.Crypto.Types
import Network.TLS.Struct
import Network.TLS.Types (HostName)

import Network.TLS.Imports
import Network.TLS.Packet (
    getBinaryVersion,
    getDNames,
    getSignatureHashAlgorithm,
    putBinaryVersion,
    putDNames,
    putSignatureHashAlgorithm,
 )
import Network.TLS.Wire

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
    , EID_ExtendedMasterSecret
    , EID_SessionTicket
    , EID_PreSharedKey
    , EID_EarlyData
    , EID_SupportedVersions
    , EID_Cookie
    , EID_PskKeyExchangeModes
    , EID_KeyShare
    , EID_SignatureAlgorithmsCert
    , EID_CertificateAuthorities
    , EID_SecureRenegotiation
    , EID_QuicTransportParameters
    ]

-- | all supported extensions by the implementation
supportedExtensions :: [ExtensionID]
supportedExtensions =
    [ EID_ServerName
    , EID_MaxFragmentLength
    , EID_ApplicationLayerProtocolNegotiation
    , EID_ExtendedMasterSecret
    , EID_SecureRenegotiation
    , EID_SupportedGroups
    , EID_EcPointFormats
    , EID_SignatureAlgorithms
    , EID_SignatureAlgorithmsCert
    , EID_KeyShare
    , EID_PreSharedKey
    , EID_EarlyData
    , EID_SupportedVersions
    , EID_Cookie
    , EID_PskKeyExchangeModes
    , EID_CertificateAuthorities
    , EID_QuicTransportParameters
    ]

------------------------------------------------------------

data MessageType
    = MsgTClientHello
    | MsgTServerHello
    | MsgTHelloRetryRequest
    | MsgTEncryptedExtensions
    | MsgTNewSessionTicket
    | MsgTCertificateRequest
    deriving (Eq, Show)

-- | Extension class to transform bytes to and from a high level Extension type.
class Extension a where
    extensionID :: a -> ExtensionID
    extensionDecode :: MessageType -> ByteString -> Maybe a
    extensionEncode :: a -> ByteString

------------------------------------------------------------

-- | Server Name extension including the name type and the associated name.
-- the associated name decoding is dependant of its name type.
-- name type = 0 : hostname
newtype ServerName = ServerName [ServerNameType] deriving (Show, Eq)

data ServerNameType
    = ServerNameHostName HostName
    | ServerNameOther (Word8, ByteString)
    deriving (Show, Eq)

instance Extension ServerName where
    extensionID _ = EID_ServerName
    extensionEncode (ServerName l) = runPut $ putOpaque16 (runPut $ mapM_ encodeNameType l)
      where
        encodeNameType (ServerNameHostName hn) = putWord8 0 >> putOpaque16 (BC.pack hn) -- FIXME: should be puny code conversion
        encodeNameType (ServerNameOther (nt, opaque)) = putWord8 nt >> putBytes opaque
    extensionDecode MsgTClientHello = decodeServerName
    extensionDecode MsgTServerHello = decodeServerName
    extensionDecode MsgTEncryptedExtensions = decodeServerName
    extensionDecode _ = error "extensionDecode: ServerName"

decodeServerName :: ByteString -> Maybe ServerName
decodeServerName = runGetMaybe $ do
    len <- fromIntegral <$> getWord16
    ServerName <$> getList len getServerName
  where
    getServerName = do
        ty <- getWord8
        snameParsed <- getOpaque16
        let !sname = B.copy snameParsed
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

-- | Secure Renegotiation
data SecureRenegotiation = SecureRenegotiation ByteString (Maybe ByteString)
    deriving (Show, Eq)

instance Extension SecureRenegotiation where
    extensionID _ = EID_SecureRenegotiation
    extensionEncode (SecureRenegotiation cvd svd) =
        runPut $ putOpaque8 (cvd `B.append` fromMaybe B.empty svd)
    extensionDecode msgtype = runGetMaybe $ do
        opaque <- getOpaque8
        case msgtype of
            MsgTServerHello ->
                let (cvd, svd) = B.splitAt (B.length opaque `div` 2) opaque
                 in return $ SecureRenegotiation cvd (Just svd)
            MsgTClientHello -> return $ SecureRenegotiation opaque Nothing
            _ -> error "extensionDecode: SecureRenegotiation"

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
        let !alpn = B.copy alpnParsed
        return (B.length alpn + 1, alpn)

------------------------------------------------------------

-- | Extended Master Secret
data ExtendedMasterSecret = ExtendedMasterSecret deriving (Show, Eq)

instance Extension ExtendedMasterSecret where
    extensionID _ = EID_ExtendedMasterSecret
    extensionEncode ExtendedMasterSecret = B.empty
    extensionDecode MsgTClientHello _ = Just ExtendedMasterSecret
    extensionDecode MsgTServerHello _ = Just ExtendedMasterSecret
    extensionDecode _ _ = error "extensionDecode: ExtendedMasterSecret"

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

-- Fixme: this is incomplete
-- newtype SessionTicket = SessionTicket ByteString
data SessionTicket = SessionTicket
    deriving (Show, Eq)

instance Extension SessionTicket where
    extensionID _ = EID_SessionTicket
    extensionEncode SessionTicket{} = runPut $ return ()
    extensionDecode MsgTClientHello = runGetMaybe (return SessionTicket)
    extensionDecode MsgTServerHello = runGetMaybe (return SessionTicket)
    extensionDecode _ = error "extensionDecode: SessionTicket"

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
    return $ SignatureAlgorithms sas

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

data SupportedVersions
    = SupportedVersionsClientHello [Version]
    | SupportedVersionsServerHello Version
    deriving (Show, Eq)

instance Extension SupportedVersions where
    extensionID _ = EID_SupportedVersions
    extensionEncode (SupportedVersionsClientHello vers) = runPut $ do
        putWord8 (fromIntegral (length vers * 2))
        mapM_ putBinaryVersion vers
    extensionEncode (SupportedVersionsServerHello ver) =
        runPut $
            putBinaryVersion ver
    extensionDecode MsgTClientHello = runGetMaybe $ do
        len <- fromIntegral <$> getWord8
        SupportedVersionsClientHello <$> getList len getVer
      where
        getVer = do
            ver <- getBinaryVersion
            return (2, ver)
    extensionDecode MsgTServerHello =
        runGetMaybe (SupportedVersionsServerHello <$> getBinaryVersion)
    extensionDecode _ = error "extensionDecode: SupportedVersionsServerHello"

------------------------------------------------------------

data KeyShareEntry = KeyShareEntry
    { keyShareEntryGroup :: Group
    , keyShareEntryKeyExchange :: ByteString
    }
    deriving (Show, Eq)

getKeyShareEntry :: Get (Int, Maybe KeyShareEntry)
getKeyShareEntry = do
    grp <- Group <$> getWord16
    l <- fromIntegral <$> getWord16
    key <- getBytes l
    let !len = l + 4
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
    deriving (Show, Eq)

instance Extension KeyShare where
    extensionID _ = EID_KeyShare
    extensionEncode (KeyShareClientHello kses) = runPut $ do
        let !len = sum [B.length key + 4 | KeyShareEntry _ key <- kses]
        putWord16 $ fromIntegral len
        mapM_ putKeyShareEntry kses
    extensionEncode (KeyShareServerHello kse) = runPut $ putKeyShareEntry kse
    extensionEncode (KeyShareHRR (Group grp)) = runPut $ putWord16 grp
    extensionDecode MsgTServerHello = runGetMaybe $ do
        (_, ment) <- getKeyShareEntry
        case ment of
            Nothing -> fail "decoding KeyShare for ServerHello"
            Just ent -> return $ KeyShareServerHello ent
    extensionDecode MsgTClientHello = runGetMaybe $ do
        len <- fromIntegral <$> getWord16
        --      len == 0 allows for HRR
        grps <- getList len getKeyShareEntry
        return $ KeyShareClientHello $ catMaybes grps
    extensionDecode MsgTHelloRetryRequest =
        runGetMaybe $
            KeyShareHRR . Group <$> getWord16
    extensionDecode _ = error "extensionDecode: KeyShare"

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
    extensionDecode MsgTClientHello =
        runGetMaybe $
            PskKeyExchangeModes . map PskKexMode <$> getWords8
    extensionDecode _ = error "extensionDecode: PskKeyExchangeModes"

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

newtype Cookie = Cookie ByteString deriving (Eq, Show)

instance Extension Cookie where
    extensionID _ = EID_Cookie
    extensionEncode (Cookie opaque) = runPut $ putOpaque16 opaque
    extensionDecode MsgTServerHello = runGetMaybe (Cookie <$> getOpaque16)
    extensionDecode _ = error "extensionDecode: Cookie"

------------------------------------------------------------

newtype CertificateAuthorities = CertificateAuthorities [DistinguishedName]
    deriving (Eq, Show)

instance Extension CertificateAuthorities where
    extensionID _ = EID_CertificateAuthorities
    extensionEncode (CertificateAuthorities names) =
        runPut $
            putDNames names
    extensionDecode MsgTClientHello =
        runGetMaybe (CertificateAuthorities <$> getDNames)
    extensionDecode MsgTCertificateRequest =
        runGetMaybe (CertificateAuthorities <$> getDNames)
    extensionDecode _ = error "extensionDecode: CertificateAuthorities"
