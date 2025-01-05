{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

-- | The Packet module contains everything necessary to serialize and
--  deserialize things with only explicit parameters, no TLS state is
--  involved here.
module Network.TLS.Packet (
    -- * params for encoding and decoding
    CurrentParams (..),

    -- * marshall functions for header messages
    decodeHeader,
    encodeHeader,

    -- * marshall functions for alert messages
    decodeAlert,
    decodeAlerts,
    encodeAlerts,

    -- * marshall functions for handshake messages
    decodeHandshakeRecord,
    decodeHandshake,
    encodeHandshake,
    encodeCertificate,

    -- * marshall functions for change cipher spec message
    decodeChangeCipherSpec,
    encodeChangeCipherSpec,
    decodePreMainSecret,
    encodePreMainSecret,
    encodeSignedDHParams,
    encodeSignedECDHParams,
    decodeReallyServerKeyXchgAlgorithmData,

    -- * generate things for packet content
    generateMainSecret,
    generateExtendedMainSecret,
    generateKeyBlock,
    generateClientFinished,
    generateServerFinished,

    -- * for extensions parsing
    getSignatureHashAlgorithm,
    putSignatureHashAlgorithm,
    getBinaryVersion,
    putBinaryVersion,
    getClientRandom32,
    putClientRandom32,
    getServerRandom32,
    putServerRandom32,
    getExtensions,
    putExtension,
    getSession,
    putSession,
    putDNames,
    getDNames,
    getHandshakeType,
) where

import Data.ByteArray (ByteArrayAccess)
import qualified Data.ByteArray as B (convert)
import qualified Data.ByteString as B
import Data.X509 (
    CertificateChain,
    CertificateChainRaw (..),
    decodeCertificateChain,
    encodeCertificateChain,
 )

import Network.TLS.Crypto
import Network.TLS.Imports
import Network.TLS.MAC
import Network.TLS.Struct
import Network.TLS.Types
import Network.TLS.Util.ASN1
import Network.TLS.Wire

data CurrentParams = CurrentParams
    { cParamsVersion :: Version
    -- ^ current protocol version
    , cParamsKeyXchgType :: Maybe CipherKeyExchangeType
    -- ^ current key exchange type
    }
    deriving (Show, Eq)

{- marshall helpers -}
getBinaryVersion :: Get Version
getBinaryVersion = Version <$> getWord16

putBinaryVersion :: Version -> Put
putBinaryVersion (Version ver) = putWord16 ver

getHeaderType :: Get ProtocolType
getHeaderType = ProtocolType <$> getWord8

putHeaderType :: ProtocolType -> Put
putHeaderType (ProtocolType pt) = putWord8 pt

getHandshakeType :: Get HandshakeType
getHandshakeType = HandshakeType <$> getWord8

{-
 - decode and encode headers
 -}
decodeHeader :: ByteString -> Either TLSError Header
decodeHeader =
    runGetErr "header" $ Header <$> getHeaderType <*> getBinaryVersion <*> getWord16

encodeHeader :: Header -> ByteString
encodeHeader (Header pt ver len) = runPut (putHeaderType pt >> putBinaryVersion ver >> putWord16 len)

{- FIXME check len <= 2^14 -}

{-
 - decode and encode ALERT
 -}
decodeAlert :: Get (AlertLevel, AlertDescription)
decodeAlert = do
    al <- AlertLevel <$> getWord8
    ad <- AlertDescription <$> getWord8
    return (al, ad)

decodeAlerts :: ByteString -> Either TLSError [(AlertLevel, AlertDescription)]
decodeAlerts = runGetErr "alerts" loop
  where
    loop = do
        r <- remaining
        if r == 0
            then return []
            else (:) <$> decodeAlert <*> loop

encodeAlerts :: [(AlertLevel, AlertDescription)] -> ByteString
encodeAlerts l = runPut $ mapM_ encodeAlert l
  where
    encodeAlert (al, ad) = putWord8 (fromAlertLevel al) >> putWord8 (fromAlertDescription ad)

{- decode and encode HANDSHAKE -}
decodeHandshakeRecord :: ByteString -> GetResult (HandshakeType, ByteString)
decodeHandshakeRecord = runGet "handshake-record" $ do
    ty <- getHandshakeType
    content <- getOpaque24
    return (ty, content)

{- FOURMOLU_DISABLE -}
decodeHandshake
    :: CurrentParams -> HandshakeType -> ByteString -> Either TLSError Handshake
decodeHandshake cp ty = runGetErr ("handshake[" ++ show ty ++ "]") $ case ty of
    HandshakeType_HelloRequest     -> decodeHelloRequest
    HandshakeType_ClientHello      -> decodeClientHello
    HandshakeType_ServerHello      -> decodeServerHello
    HandshakeType_Certificate      -> decodeCertificate
    HandshakeType_ServerKeyXchg    -> decodeServerKeyXchg cp
    HandshakeType_CertRequest      -> decodeCertRequest cp
    HandshakeType_ServerHelloDone  -> decodeServerHelloDone
    HandshakeType_CertVerify       -> decodeCertVerify cp
    HandshakeType_ClientKeyXchg    -> decodeClientKeyXchg cp
    HandshakeType_Finished         -> decodeFinished
    HandshakeType_NewSessionTicket -> decodeNewSessionTicket
    x -> fail $ "Unsupported HandshakeType " ++ show x
{- FOURMOLU_ENABLE -}

decodeHelloRequest :: Get Handshake
decodeHelloRequest = return HelloRequest

decodeClientHello :: Get Handshake
decodeClientHello = do
    ver <- getBinaryVersion
    random <- getClientRandom32
    session <- getSession
    ciphers <- map CipherId <$> getWords16
    compressions <- getWords8
    r <- remaining
    exts <-
        if r > 0
            then fromIntegral <$> getWord16 >>= getExtensions
            else return []
    r1 <- remaining
    when (r1 /= 0) $ fail "Client hello"
    let ch = CH session ciphers exts
    return $ ClientHello ver random compressions ch

decodeServerHello :: Get Handshake
decodeServerHello = do
    ver <- getBinaryVersion
    random <- getServerRandom32
    session <- getSession
    cipherid <- CipherId <$> getWord16
    compressionid <- getWord8
    r <- remaining
    exts <-
        if r > 0
            then fromIntegral <$> getWord16 >>= getExtensions
            else return []
    return $ ServerHello ver random session cipherid compressionid exts

decodeServerHelloDone :: Get Handshake
decodeServerHelloDone = return ServerHelloDone

decodeCertificate :: Get Handshake
decodeCertificate = do
    certsRaw <-
        CertificateChainRaw
            <$> (getWord24 >>= \len -> getList (fromIntegral len) getCertRaw)
    case decodeCertificateChain certsRaw of
        Left (i, s) -> fail ("error certificate parsing " ++ show i ++ ":" ++ s)
        Right cc -> return $ Certificate $ TLSCertificateChain cc
  where
    getCertRaw = getOpaque24 >>= \cert -> return (3 + B.length cert, cert)

decodeFinished :: Get Handshake
decodeFinished = Finished . VerifyData <$> (remaining >>= getBytes)

decodeNewSessionTicket :: Get Handshake
decodeNewSessionTicket = NewSessionTicket <$> getWord32 <*> getOpaque16

decodeCertRequest :: CurrentParams -> Get Handshake
decodeCertRequest _cp = do
    certTypes <- map CertificateType <$> getWords8
    sigHashAlgs <- getWord16 >>= getSignatureHashAlgorithms
    CertRequest certTypes sigHashAlgs <$> getDNames
  where
    getSignatureHashAlgorithms len =
        getList (fromIntegral len) (getSignatureHashAlgorithm >>= \sh -> return (2, sh))

-- | Decode a list CA distinguished names
getDNames :: Get [DistinguishedName]
getDNames = do
    dNameLen <- getWord16
    -- FIXME: Decide whether to remove this check completely or to make it an option.
    -- when (cParamsVersion cp < TLS12 && dNameLen < 3) $ fail "certrequest distinguishname not of the correct size"
    getList (fromIntegral dNameLen) getDName
  where
    getDName = do
        dName <- getOpaque16
        when (B.length dName == 0) $ fail "certrequest: invalid DN length"
        dn <-
            either fail return $ decodeASN1Object "cert request DistinguishedName" dName
        return (2 + B.length dName, dn)

decodeCertVerify :: CurrentParams -> Get Handshake
decodeCertVerify cp = CertVerify <$> getDigitallySigned (cParamsVersion cp)

decodeClientKeyXchg :: CurrentParams -> Get Handshake
decodeClientKeyXchg cp =
    -- case  ClientKeyXchg <$> (remaining >>= getBytes)
    case cParamsKeyXchgType cp of
        Nothing -> fail "no client key exchange type"
        Just cke -> ClientKeyXchg <$> parseCKE cke
  where
    parseCKE CipherKeyExchange_RSA = CKX_RSA <$> (remaining >>= getBytes)
    parseCKE CipherKeyExchange_DHE_RSA = parseClientDHPublic
    parseCKE CipherKeyExchange_DHE_DSA = parseClientDHPublic
    parseCKE CipherKeyExchange_DH_Anon = parseClientDHPublic
    parseCKE CipherKeyExchange_ECDHE_RSA = parseClientECDHPublic
    parseCKE CipherKeyExchange_ECDHE_ECDSA = parseClientECDHPublic
    parseCKE _ = fail "unsupported client key exchange type"
    parseClientDHPublic = CKX_DH . dhPublic <$> getInteger16
    parseClientECDHPublic = CKX_ECDH <$> getOpaque8

decodeServerKeyXchg_DH :: Get ServerDHParams
decodeServerKeyXchg_DH = getServerDHParams

-- We don't support ECDH_Anon at this moment
-- decodeServerKeyXchg_ECDH :: Get ServerECDHParams

decodeServerKeyXchg_RSA :: Get ServerRSAParams
decodeServerKeyXchg_RSA =
    ServerRSAParams
        <$> getInteger16 -- modulus
        <*> getInteger16 -- exponent

decodeServerKeyXchgAlgorithmData
    :: Version
    -> CipherKeyExchangeType
    -> Get ServerKeyXchgAlgorithmData
decodeServerKeyXchgAlgorithmData ver cke = toCKE
  where
    toCKE = case cke of
        CipherKeyExchange_RSA -> SKX_RSA . Just <$> decodeServerKeyXchg_RSA
        CipherKeyExchange_DH_Anon -> SKX_DH_Anon <$> decodeServerKeyXchg_DH
        CipherKeyExchange_DHE_RSA -> do
            dhparams <- getServerDHParams
            signature <- getDigitallySigned ver
            return $ SKX_DHE_RSA dhparams signature
        CipherKeyExchange_DHE_DSA -> do
            dhparams <- getServerDHParams
            signature <- getDigitallySigned ver
            return $ SKX_DHE_DSA dhparams signature
        CipherKeyExchange_ECDHE_RSA -> do
            ecdhparams <- getServerECDHParams
            signature <- getDigitallySigned ver
            return $ SKX_ECDHE_RSA ecdhparams signature
        CipherKeyExchange_ECDHE_ECDSA -> do
            ecdhparams <- getServerECDHParams
            signature <- getDigitallySigned ver
            return $ SKX_ECDHE_ECDSA ecdhparams signature
        _ -> do
            bs <- remaining >>= getBytes
            return $ SKX_Unknown bs

decodeServerKeyXchg :: CurrentParams -> Get Handshake
decodeServerKeyXchg cp =
    case cParamsKeyXchgType cp of
        Just cke -> ServerKeyXchg <$> decodeServerKeyXchgAlgorithmData (cParamsVersion cp) cke
        Nothing -> ServerKeyXchg . SKX_Unparsed <$> (remaining >>= getBytes)

encodeHandshake :: Handshake -> ByteString
encodeHandshake o =
    let content = encodeHandshake' o
     in let len = B.length content
         in let header = runPut $ encodeHandshakeHeader (typeOfHandshake o) len
             in B.concat [header, content]

encodeHandshakeHeader :: HandshakeType -> Int -> Put
encodeHandshakeHeader ty len = putWord8 (fromHandshakeType ty) >> putWord24 len

encodeHandshake' :: Handshake -> ByteString
encodeHandshake' (ClientHello version random compressionIDs CH{..}) = runPut $ do
    putBinaryVersion version
    putClientRandom32 random
    putSession chSession
    putWords16 $ map fromCipherId chCiphers
    putWords8 compressionIDs
    putExtensions chExtensions
    return ()
encodeHandshake' (ServerHello version random session cipherid compressionID exts) = runPut $ do
    putBinaryVersion version
    putServerRandom32 random
    putSession session
    putWord16 $ fromCipherId cipherid
    putWord8 compressionID
    putExtensions exts
    return ()
encodeHandshake' (Certificate (TLSCertificateChain cc)) = encodeCertificate cc
encodeHandshake' (ClientKeyXchg ckx) = runPut $ do
    case ckx of
        CKX_RSA encryptedPreMain -> putBytes encryptedPreMain
        CKX_DH clientDHPublic -> putInteger16 $ dhUnwrapPublic clientDHPublic
        CKX_ECDH bytes -> putOpaque8 bytes
encodeHandshake' (ServerKeyXchg skg) = runPut $
    case skg of
        SKX_RSA _ -> error "encodeHandshake' SKX_RSA not implemented"
        SKX_DH_Anon params -> putServerDHParams params
        SKX_DHE_RSA params sig -> putServerDHParams params >> putDigitallySigned sig
        SKX_DHE_DSA params sig -> putServerDHParams params >> putDigitallySigned sig
        SKX_ECDHE_RSA params sig -> putServerECDHParams params >> putDigitallySigned sig
        SKX_ECDHE_ECDSA params sig -> putServerECDHParams params >> putDigitallySigned sig
        SKX_Unparsed bytes -> putBytes bytes
        _ -> error ("encodeHandshake': cannot handle: " ++ show skg)
encodeHandshake' HelloRequest = ""
encodeHandshake' ServerHelloDone = ""
encodeHandshake' (CertRequest certTypes sigAlgs certAuthorities) = runPut $ do
    putWords8 (map fromCertificateType certTypes)
    putWords16 $
        map
            ( \(HashAlgorithm x, SignatureAlgorithm y) -> fromIntegral x * 256 + fromIntegral y
            )
            sigAlgs
    putDNames certAuthorities
encodeHandshake' (CertVerify digitallySigned) = runPut $ putDigitallySigned digitallySigned
encodeHandshake' (Finished (VerifyData opaque)) = runPut $ putBytes opaque
encodeHandshake' (NewSessionTicket life ticket) = runPut $ do
    putWord32 life
    putOpaque16 ticket

------------------------------------------------------------

-- | Encode a list of distinguished names.
putDNames :: [DistinguishedName] -> Put
putDNames dnames = do
    enc <- mapM encodeCA dnames
    let totLength = sum $ map ((+) 2 . B.length) enc
    putWord16 (fromIntegral totLength)
    mapM_ (\b -> putWord16 (fromIntegral (B.length b)) >> putBytes b) enc
  where
    -- Convert a distinguished name to its DER encoding.
    encodeCA dn = return $ encodeASN1Object dn

{- FIXME make sure it return error if not 32 available -}
getRandom32 :: Get ByteString
getRandom32 = getBytes 32

getServerRandom32 :: Get ServerRandom
getServerRandom32 = ServerRandom <$> getRandom32

getClientRandom32 :: Get ClientRandom
getClientRandom32 = ClientRandom <$> getRandom32

putRandom32 :: ByteString -> Put
putRandom32 = putBytes

putClientRandom32 :: ClientRandom -> Put
putClientRandom32 (ClientRandom r) = putRandom32 r

putServerRandom32 :: ServerRandom -> Put
putServerRandom32 (ServerRandom r) = putRandom32 r

getSession :: Get Session
getSession = do
    len8 <- getWord8
    case fromIntegral len8 of
        0 -> return $ Session Nothing
        len
            | len > 32 -> fail "the length of session id must be <= 32"
            | otherwise -> Session . Just <$> getBytes len

putSession :: Session -> Put
putSession (Session Nothing) = putWord8 0
putSession (Session (Just s)) = putOpaque8 s

getExtensions :: Int -> Get [ExtensionRaw]
getExtensions 0 = return []
getExtensions len = do
    extty <- ExtensionID <$> getWord16
    extdatalen <- getWord16
    extdata <- getBytes $ fromIntegral extdatalen
    extxs <- getExtensions (len - fromIntegral extdatalen - 4)
    return $ ExtensionRaw extty extdata : extxs

putExtension :: ExtensionRaw -> Put
putExtension (ExtensionRaw (ExtensionID ty) l) = putWord16 ty >> putOpaque16 l

putExtensions :: [ExtensionRaw] -> Put
putExtensions [] = return ()
putExtensions es = putOpaque16 (runPut $ mapM_ putExtension es)

getSignatureHashAlgorithm :: Get HashAndSignatureAlgorithm
getSignatureHashAlgorithm = do
    h <- HashAlgorithm <$> getWord8
    s <- SignatureAlgorithm <$> getWord8
    return (h, s)

putSignatureHashAlgorithm :: HashAndSignatureAlgorithm -> Put
putSignatureHashAlgorithm (HashAlgorithm h, SignatureAlgorithm s) =
    putWord8 h >> putWord8 s

getServerDHParams :: Get ServerDHParams
getServerDHParams = ServerDHParams <$> getBigNum16 <*> getBigNum16 <*> getBigNum16

putServerDHParams :: ServerDHParams -> Put
putServerDHParams (ServerDHParams p g y) = mapM_ putBigNum16 [p, g, y]

-- RFC 4492 Section 5.4 Server Key Exchange
getServerECDHParams :: Get ServerECDHParams
getServerECDHParams = do
    curveType <- getWord8
    case curveType of
        3 -> do
            -- ECParameters ECCurveType: curve name type
            grp <- Group <$> getWord16 -- ECParameters NamedCurve
            mxy <- getOpaque8 -- ECPoint
            case decodeGroupPublic grp mxy of
                Left e -> fail $ "getServerECDHParams: " ++ show e
                Right grppub -> return $ ServerECDHParams grp grppub
        _ -> fail "getServerECDHParams: unknown type for ECDH Params"

-- RFC 4492 Section 5.4 Server Key Exchange
putServerECDHParams :: ServerECDHParams -> Put
putServerECDHParams (ServerECDHParams (Group grp) grppub) = do
    putWord8 3 -- ECParameters ECCurveType
    putWord16 grp -- ECParameters NamedCurve
    putOpaque8 $ encodeGroupPublic grppub -- ECPoint

getDigitallySigned :: Version -> Get DigitallySigned
getDigitallySigned _ver =
    DigitallySigned
        <$> getSignatureHashAlgorithm
        <*> getOpaque16

putDigitallySigned :: DigitallySigned -> Put
putDigitallySigned (DigitallySigned h sig) =
    putSignatureHashAlgorithm h >> putOpaque16 sig

{-
 - decode and encode ALERT
 -}

decodeChangeCipherSpec :: ByteString -> Either TLSError ()
decodeChangeCipherSpec = runGetErr "changecipherspec" $ do
    x <- getWord8
    when (x /= 1) $ fail "unknown change cipher spec content"
    len <- remaining
    when (len /= 0) $ fail "the length of CSS must be 1"

encodeChangeCipherSpec :: ByteString
encodeChangeCipherSpec = runPut (putWord8 1)

-- RSA pre-main secret
decodePreMainSecret :: ByteString -> Either TLSError (Version, ByteString)
decodePreMainSecret =
    runGetErr "pre-main-secret" $
        (,) <$> getBinaryVersion <*> getBytes 46

encodePreMainSecret :: Version -> ByteString -> ByteString
encodePreMainSecret version bytes = runPut (putBinaryVersion version >> putBytes bytes)

-- | in certain cases, we haven't manage to decode ServerKeyExchange properly,
-- because the decoding was too eager and the cipher wasn't been set yet.
-- we keep the Server Key Exchange in it unparsed format, and this function is
-- able to really decode the server key xchange if it's unparsed.
decodeReallyServerKeyXchgAlgorithmData
    :: Version
    -> CipherKeyExchangeType
    -> ByteString
    -> Either TLSError ServerKeyXchgAlgorithmData
decodeReallyServerKeyXchgAlgorithmData ver cke =
    runGetErr
        "server-key-xchg-algorithm-data"
        (decodeServerKeyXchgAlgorithmData ver cke)

{-
 - generate things for packet content
 -}
type PRF = ByteString -> ByteString -> Int -> ByteString

-- | The TLS12 PRF is cipher specific, and some TLS12 algorithms use SHA384
-- instead of the default SHA256.
getPRF :: Version -> Cipher -> PRF
getPRF ver ciph
    | ver < TLS12 = prf_MD5SHA1
    | maybe True (< TLS12) (cipherMinVer ciph) = prf_SHA256
    | otherwise = prf_TLS ver $ fromMaybe SHA256 $ cipherPRFHash ciph

generateMainSecret_TLS
    :: ByteArrayAccess preMain
    => PRF
    -> preMain
    -> ClientRandom
    -> ServerRandom
    -> ByteString
generateMainSecret_TLS prf preMainSecret (ClientRandom c) (ServerRandom s) =
    prf (B.convert preMainSecret) seed 48
  where
    seed = B.concat ["master secret", c, s]

generateMainSecret
    :: ByteArrayAccess preMain
    => Version
    -> Cipher
    -> preMain
    -> ClientRandom
    -> ServerRandom
    -> ByteString
generateMainSecret v c = generateMainSecret_TLS $ getPRF v c

generateExtendedMainSecret
    :: ByteArrayAccess preMain
    => Version
    -> Cipher
    -> preMain
    -> ByteString
    -> ByteString
generateExtendedMainSecret v c preMainSecret sessionHash =
    getPRF v c (B.convert preMainSecret) seed 48
  where
    seed = B.append "extended master secret" sessionHash

generateKeyBlock_TLS
    :: PRF -> ClientRandom -> ServerRandom -> ByteString -> Int -> ByteString
generateKeyBlock_TLS prf (ClientRandom c) (ServerRandom s) mainSecret kbsize =
    prf mainSecret seed kbsize
  where
    seed = B.concat ["key expansion", s, c]

generateKeyBlock
    :: Version
    -> Cipher
    -> ClientRandom
    -> ServerRandom
    -> ByteString
    -> Int
    -> ByteString
generateKeyBlock v c = generateKeyBlock_TLS $ getPRF v c

generateFinished_TLS :: PRF -> ByteString -> ByteString -> HashCtx -> ByteString
generateFinished_TLS prf label mainSecret hashctx = prf mainSecret seed 12
  where
    seed = B.concat [label, hashFinal hashctx]

generateClientFinished
    :: Version
    -> Cipher
    -> ByteString
    -> HashCtx
    -> ByteString
generateClientFinished ver ciph =
    generateFinished_TLS (getPRF ver ciph) "client finished"

generateServerFinished
    :: Version
    -> Cipher
    -> ByteString
    -> HashCtx
    -> ByteString
generateServerFinished ver ciph =
    generateFinished_TLS (getPRF ver ciph) "server finished"

encodeSignedDHParams
    :: ServerDHParams -> ClientRandom -> ServerRandom -> ByteString
encodeSignedDHParams dhparams cran sran =
    runPut $
        putClientRandom32 cran >> putServerRandom32 sran >> putServerDHParams dhparams

-- Combination of RFC 5246 and 4492 is ambiguous.
-- Let's assume ecdhe_rsa and ecdhe_dss are identical to
-- dhe_rsa and dhe_dss.
encodeSignedECDHParams
    :: ServerECDHParams -> ClientRandom -> ServerRandom -> ByteString
encodeSignedECDHParams dhparams cran sran =
    runPut $
        putClientRandom32 cran >> putServerRandom32 sran >> putServerECDHParams dhparams

encodeCertificate :: CertificateChain -> ByteString
encodeCertificate cc = runPut $ putOpaque24 (runPut $ mapM_ putOpaque24 certs)
  where
    (CertificateChainRaw certs) = encodeCertificateChain cc
