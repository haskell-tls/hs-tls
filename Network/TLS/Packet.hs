{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Network.TLS.Packet
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Packet module contains everything necessary to serialize and deserialize things
-- with only explicit parameters, no TLS state is involved here.
--
module Network.TLS.Packet
        (
        -- * params for encoding and decoding
          CurrentParams(..)
        -- * marshall functions for header messages
        , decodeHeader
        , encodeHeader
        , encodeHeaderNoVer -- use for SSL3

        -- * marshall functions for alert messages
        , decodeAlert
        , decodeAlerts
        , encodeAlerts

        -- * marshall functions for handshake messages
        , decodeHandshakes
        , decodeHandshake
        , encodeHandshake
        , encodeHandshakes
        , encodeHandshakeHeader
        , encodeHandshakeContent

        -- * marshall functions for change cipher spec message
        , decodeChangeCipherSpec
        , encodeChangeCipherSpec

        , decodePreMasterSecret
        , encodePreMasterSecret

        -- * generate things for packet content
        , generateMasterSecret
        , generateKeyBlock
        , generateClientFinished
        , generateServerFinished

        , generateCertificateVerify_SSL
        ) where

import Network.TLS.Struct
import Network.TLS.Wire
import Network.TLS.Cap
import Data.Either (partitionEithers)
import Data.Maybe (fromJust)
import Data.Bits ((.|.))
import Data.Word(Word16)
import Control.Applicative ((<$>))
import Control.Monad
import Data.Certificate.X509 (decodeCertificate, encodeCertificate, X509, encodeDN, decodeDN)
import Network.TLS.Crypto
import Network.TLS.MAC
import Network.TLS.Cipher (CipherKeyExchangeType(..))
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy as L

import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.MD5 as MD5

data CurrentParams = CurrentParams
        { cParamsVersion     :: Version               -- ^ current protocol version
        , cParamsKeyXchgType :: CipherKeyExchangeType -- ^ current key exchange type
        , cParamsSupportNPN  :: Bool                  -- ^ support Next Protocol Negotiation extension
        } deriving (Show,Eq)

{- marshall helpers -}
getVersion :: Get Version
getVersion = do
        major <- getWord8
        minor <- getWord8
        case verOfNum (major, minor) of
                Nothing -> fail ("invalid version : " ++ show major ++ "," ++ show minor)
                Just v  -> return v

putVersion :: Version -> Put
putVersion ver = putWord8 major >> putWord8 minor
        where (major, minor) = numericalVer ver

getHeaderType :: Get ProtocolType
getHeaderType = do
        ty <- getWord8
        case valToType ty of
                Nothing -> fail ("invalid header type: " ++ show ty)
                Just t  -> return t

putHeaderType :: ProtocolType -> Put
putHeaderType = putWord8 . valOfType

getHandshakeType :: Get HandshakeType
getHandshakeType = do
        ty <- getWord8
        case valToType ty of
                Nothing -> fail ("invalid handshake type: " ++ show ty)
                Just t  -> return t

{-
 - decode and encode headers
 -}
decodeHeader :: ByteString -> Either TLSError Header
decodeHeader = runGetErr "header" $ liftM3 Header getHeaderType getVersion getWord16

encodeHeader :: Header -> ByteString
encodeHeader (Header pt ver len) = runPut (putHeaderType pt >> putVersion ver >> putWord16 len)
        {- FIXME check len <= 2^14 -}

encodeHeaderNoVer :: Header -> ByteString
encodeHeaderNoVer (Header pt _ len) = runPut (putHeaderType pt >> putWord16 len)
        {- FIXME check len <= 2^14 -}

{-
 - decode and encode ALERT
 -}
decodeAlert :: Get (AlertLevel, AlertDescription)
decodeAlert = do
        al <- getWord8
        ad <- getWord8
        case (valToType al, valToType ad) of
                (Just a, Just d) -> return (a, d)
                (Nothing, _)     -> fail "cannot decode alert level"
                (_, Nothing)     -> fail "cannot decode alert description"

decodeAlerts :: ByteString -> Either TLSError [(AlertLevel, AlertDescription)]
decodeAlerts = runGetErr "alerts" $ loop
        where loop = do
                r <- remaining
                if r == 0
                        then return []
                        else liftM2 (:) decodeAlert loop

encodeAlerts :: [(AlertLevel, AlertDescription)] -> ByteString
encodeAlerts l = runPut $ mapM_ encodeAlert l
        where encodeAlert (al, ad) = putWord8 (valOfType al) >> putWord8 (valOfType ad)

{- decode and encode HANDSHAKE -}
decodeHandshakeHeader :: Get (HandshakeType, Bytes)
decodeHandshakeHeader = do
        ty      <- getHandshakeType
        content <- getOpaque24
        return (ty, content)

decodeHandshakes :: ByteString -> Either TLSError [(HandshakeType, Bytes)]
decodeHandshakes b = runGetErr "handshakes" getAll b where
        getAll = do
                x <- decodeHandshakeHeader
                empty <- isEmpty
                if empty
                        then return [x]
                        else liftM ((:) x) getAll

decodeHandshake :: CurrentParams -> HandshakeType -> ByteString -> Either TLSError Handshake
decodeHandshake cp ty = runGetErr "handshake" $ case ty of
        HandshakeType_HelloRequest    -> decodeHelloRequest
        HandshakeType_ClientHello     -> decodeClientHello
        HandshakeType_ServerHello     -> decodeServerHello
        HandshakeType_Certificate     -> decodeCertificates
        HandshakeType_ServerKeyXchg   -> decodeServerKeyXchg cp
        HandshakeType_CertRequest     -> decodeCertRequest cp
        HandshakeType_ServerHelloDone -> decodeServerHelloDone
        HandshakeType_CertVerify      -> decodeCertVerify cp
        HandshakeType_ClientKeyXchg   -> decodeClientKeyXchg
        HandshakeType_Finished        -> decodeFinished
        HandshakeType_NPN             -> do
                unless (cParamsSupportNPN cp) $ fail "unsupported handshake type"
                decodeNextProtocolNegotiation

decodeHelloRequest :: Get Handshake
decodeHelloRequest = return HelloRequest

decodeClientHello :: Get Handshake
decodeClientHello = do
        ver          <- getVersion
        random       <- getClientRandom32
        session      <- getSession
        ciphers      <- getWords16
        compressions <- getWords8
        r            <- remaining
        exts <- if hasHelloExtensions ver && r > 0
                then fmap fromIntegral getWord16 >>= getExtensions
                else return []
        return $ ClientHello ver random session ciphers compressions exts

decodeServerHello :: Get Handshake
decodeServerHello = do
        ver           <- getVersion
        random        <- getServerRandom32
        session       <- getSession
        cipherid      <- getWord16
        compressionid <- getWord8
        r             <- remaining
        exts <- if hasHelloExtensions ver && r > 0
                then fmap fromIntegral getWord16 >>= getExtensions
                else return []
        return $ ServerHello ver random session cipherid compressionid exts

decodeServerHelloDone :: Get Handshake
decodeServerHelloDone = return ServerHelloDone

decodeCertificates :: Get Handshake
decodeCertificates = do
        certs <- getWord24 >>= getCerts >>= return . map (decodeCertificate . L.fromChunks . (:[]))
        let (l, r) = partitionEithers certs
        if length l > 0
                then fail ("error certificate parsing: " ++ show l)
                else return $ Certificates r

decodeFinished :: Get Handshake
decodeFinished = Finished <$> (remaining >>= getBytes)

decodeNextProtocolNegotiation :: Get Handshake
decodeNextProtocolNegotiation = do
        opaque <- getOpaque8
        _      <- getOpaque8 -- ignore padding
        return $ HsNextProtocolNegotiation opaque

getSignatureHashAlgorithm :: Get (HashAlgorithm, SignatureAlgorithm)
getSignatureHashAlgorithm = do
        h <- fromJust . valToType <$> getWord8
        s <- fromJust . valToType <$> getWord8
        return (h,s)

getSignatureHashAlgorithms :: Int -> Get [ (HashAlgorithm, SignatureAlgorithm) ]
getSignatureHashAlgorithms 0   = return []
getSignatureHashAlgorithms len = liftM2 (:) getSignatureHashAlgorithm (getSignatureHashAlgorithms (len-2))

decodeCertRequest :: CurrentParams -> Get Handshake
decodeCertRequest cp = do
        certTypes <- map (fromJust . valToType . fromIntegral) <$> getWords8

        sigHashAlgs <- if cParamsVersion cp >= TLS12
                then do
                        sighashlen <- getWord16
                        Just <$> getSignatureHashAlgorithms (fromIntegral sighashlen)
                else return Nothing
        dNameLen <- getWord16
        -- FIXME: Decide whether to remove this check completely or to make it an option.
        -- when (cParamsVersion cp < TLS12 && dNameLen < 3) $ fail "certrequest distinguishname not of the correct size"
        dNames <- decodeDNames dNameLen
        return $ CertRequest certTypes sigHashAlgs dNames
  where
    -- Parse a list of distinguished names, which must be exactly
    -- 'len' bytes long.
    decodeDNames :: Word16 -> Get [DistinguishedName]
    decodeDNames len | len == 0 = return []
    decodeDNames len = do
      thisLen <- getWord16
      when (thisLen == 0) $ fail "certrequest: invalid DN length"
      dName <- getBytes $ fromIntegral thisLen
      l <- decodeDNames (len - (2 + thisLen))
      dn <- decodeDName dName
      return $ dn : l

    -- Decode the given bytes into a distinguished name.
    decodeDName :: Bytes -> Get DistinguishedName
    decodeDName d =
      case decodeDN (L.fromChunks [d]) of
        Left err -> fail $ "certrequest: " ++ show err
        Right s -> return $ DistinguishedName s


decodeCertVerify :: CurrentParams -> Get Handshake
decodeCertVerify cp = do
        mbHashSig <- if cParamsVersion cp >= TLS12
                     then Just <$> getSignatureHashAlgorithm
                     else return Nothing
        bs <- getOpaque16
        return $ CertVerify mbHashSig (CertVerifyData bs)

decodeClientKeyXchg :: Get Handshake
decodeClientKeyXchg = ClientKeyXchg <$> (remaining >>= getBytes)

os2ip :: ByteString -> Integer
os2ip = B.foldl' (\a b -> (256 * a) .|. (fromIntegral b)) 0

decodeServerKeyXchg_DH :: Get ServerDHParams
decodeServerKeyXchg_DH = do
        p <- getOpaque16
        g <- getOpaque16
        y <- getOpaque16
        return $ ServerDHParams { dh_p = os2ip p, dh_g = os2ip g, dh_Ys = os2ip y }

decodeServerKeyXchg_RSA :: Get ServerRSAParams
decodeServerKeyXchg_RSA = do
        modulus <- getOpaque16
        expo    <- getOpaque16
        return $ ServerRSAParams { rsa_modulus = os2ip modulus, rsa_exponent = os2ip expo }

decodeServerKeyXchg :: CurrentParams -> Get Handshake
decodeServerKeyXchg cp = ServerKeyXchg <$> case cParamsKeyXchgType cp of
        CipherKeyExchange_RSA     -> SKX_RSA . Just <$> decodeServerKeyXchg_RSA
        CipherKeyExchange_DH_Anon -> SKX_DH_Anon <$> decodeServerKeyXchg_DH
        CipherKeyExchange_DHE_RSA -> do
                dhparams <- decodeServerKeyXchg_DH
                signature <- getOpaque16
                return $ SKX_DHE_RSA dhparams (B.unpack signature)
        CipherKeyExchange_DHE_DSS -> do
                dhparams  <- decodeServerKeyXchg_DH
                signature <- getOpaque16
                return $ SKX_DHE_DSS dhparams (B.unpack signature)
        _ -> do
                bs <- remaining >>= getBytes
                return $ SKX_Unknown bs

encodeHandshake :: Handshake -> ByteString
encodeHandshake o =
        let content = runPut $ encodeHandshakeContent o in
        let len = fromIntegral $ B.length content in
        let header = runPut $ encodeHandshakeHeader (typeOfHandshake o) len in
        B.concat [ header, content ]

encodeHandshakes :: [Handshake] -> ByteString
encodeHandshakes hss = B.concat $ map encodeHandshake hss

encodeHandshakeHeader :: HandshakeType -> Int -> Put
encodeHandshakeHeader ty len = putWord8 (valOfType ty) >> putWord24 len

encodeHandshakeContent :: Handshake -> Put

encodeHandshakeContent (ClientHello version random session cipherIDs compressionIDs exts) = do
        putVersion version
        putClientRandom32 random
        putSession session
        putWords16 cipherIDs
        putWords8 compressionIDs
        putExtensions exts
        return ()

encodeHandshakeContent (ServerHello version random session cipherID compressionID exts) =
        putVersion version >> putServerRandom32 random >> putSession session
                           >> putWord16 cipherID >> putWord8 compressionID
                           >> putExtensions exts >> return ()

encodeHandshakeContent (Certificates certs) = putOpaque24 (runPut $ mapM_ putCert certs)

encodeHandshakeContent (ClientKeyXchg content) = do
        putBytes content

encodeHandshakeContent (ServerKeyXchg _) = do
        -- FIXME
        return ()

encodeHandshakeContent (HelloRequest) = return ()
encodeHandshakeContent (ServerHelloDone) = return ()

encodeHandshakeContent (CertRequest certTypes sigAlgs certAuthorities) = do
        putWords8 (map valOfType certTypes)
        case sigAlgs of
                Nothing -> return ()
                Just l  -> putWords16 $ map (\(x,y) -> (fromIntegral $ valOfType x) * 256 + (fromIntegral $ valOfType y)) l
        encodeCertAuthorities certAuthorities
  where
    -- Convert a distinguished name to its DER encoding.
    encodeCA (DistinguishedName dn) =
      case encodeDN dn of
        Left err -> fail $ "cannot encode distinguished name: " ++ err
        Right s -> return $ B.concat $ L.toChunks s

    -- Encode a list of distinguished names.
    encodeCertAuthorities certAuths = do
      enc <- mapM encodeCA certAuths
      let totLength = sum $ map (((+) 2) . B.length) enc
      putWord16 (fromIntegral totLength)
      mapM_ (\ b -> putWord16 (fromIntegral (B.length b)) >> putBytes b) enc

encodeHandshakeContent (CertVerify mbHashSig (CertVerifyData c)) = do
        -- TLS 1.2 prepends the hash and signature algorithms to the
        -- signature.
        case mbHashSig of
          Nothing -> return ()
          Just (h, s) -> putWord16 $ (fromIntegral $ valOfType h) * 256 + (fromIntegral $ valOfType s)
        putWord16 (fromIntegral $ B.length c)
        putBytes c


encodeHandshakeContent (Finished opaque) = putBytes opaque

encodeHandshakeContent (HsNextProtocolNegotiation protocol) = do
        putOpaque8 protocol
        putOpaque8 $ B.replicate paddingLen 0
        where paddingLen = 32 - ((B.length protocol + 2) `mod` 32)

{- FIXME make sure it return error if not 32 available -}
getRandom32 :: Get Bytes
getRandom32 = getBytes 32

getServerRandom32 :: Get ServerRandom
getServerRandom32 = ServerRandom <$> getRandom32

getClientRandom32 :: Get ClientRandom
getClientRandom32 = ClientRandom <$> getRandom32

putRandom32 :: Bytes -> Put
putRandom32 = putBytes

putClientRandom32 :: ClientRandom -> Put
putClientRandom32 (ClientRandom r) = putRandom32 r

putServerRandom32 :: ServerRandom -> Put
putServerRandom32 (ServerRandom r) = putRandom32 r

getSession :: Get Session
getSession = do
        len8 <- getWord8
        case fromIntegral len8 of
                0   -> return $ Session Nothing
                len -> Session . Just <$> getBytes len

putSession :: Session -> Put
putSession (Session Nothing)  = putWord8 0
putSession (Session (Just s)) = putOpaque8 s

getCerts :: Int -> Get [Bytes]
getCerts 0   = return []
getCerts len = do
        certlen <- getWord24
        cert <- getBytes certlen
        certxs <- getCerts (len - certlen - 3)
        return (cert : certxs)

putCert :: X509 -> Put
putCert cert = putOpaque24 (B.concat $ L.toChunks $ encodeCertificate cert)

getExtensions :: Int -> Get [ExtensionRaw]
getExtensions 0   = return []
getExtensions len = do
        extty <- getWord16
        extdatalen <- getWord16
        extdata <- getBytes $ fromIntegral extdatalen
        extxs <- getExtensions (len - fromIntegral extdatalen - 4)
        return $ (extty, extdata) : extxs

putExtension :: ExtensionRaw -> Put
putExtension (ty, l) = putWord16 ty >> putOpaque16 l

putExtensions :: [ExtensionRaw] -> Put
putExtensions [] = return ()
putExtensions es = putOpaque16 (runPut $ mapM_ putExtension es)

{-
 - decode and encode ALERT
 -}

decodeChangeCipherSpec :: ByteString -> Either TLSError ()
decodeChangeCipherSpec = runGetErr "changecipherspec" $ do
        x <- getWord8
        when (x /= 1) (fail "unknown change cipher spec content")

encodeChangeCipherSpec :: ByteString
encodeChangeCipherSpec = runPut (putWord8 1)

-- rsa pre master secret
decodePreMasterSecret :: Bytes -> Either TLSError (Version, Bytes)
decodePreMasterSecret = runGetErr "pre-master-secret" $ do
        liftM2 (,) getVersion (getBytes 46)

encodePreMasterSecret :: Version -> Bytes -> Bytes
encodePreMasterSecret version bytes = runPut (putVersion version >> putBytes bytes)

{-
 - generate things for packet content
 -}
type PRF = Bytes -> Bytes -> Int -> Bytes

generateMasterSecret_SSL :: Bytes -> ClientRandom -> ServerRandom -> Bytes
generateMasterSecret_SSL premasterSecret (ClientRandom c) (ServerRandom s) =
        B.concat $ map (computeMD5) ["A","BB","CCC"]
        where
                computeMD5  label = MD5.hash $ B.concat [ premasterSecret, computeSHA1 label ]
                computeSHA1 label = SHA1.hash $ B.concat [ label, premasterSecret, c, s ]

generateMasterSecret_TLS :: PRF -> Bytes -> ClientRandom -> ServerRandom -> Bytes
generateMasterSecret_TLS prf premasterSecret (ClientRandom c) (ServerRandom s) =
        prf premasterSecret seed 48
        where
                seed = B.concat [ "master secret", c, s ]

generateMasterSecret :: Version -> Bytes -> ClientRandom -> ServerRandom -> Bytes
generateMasterSecret SSL2  = generateMasterSecret_SSL
generateMasterSecret SSL3  = generateMasterSecret_SSL
generateMasterSecret TLS10 = generateMasterSecret_TLS prf_MD5SHA1
generateMasterSecret TLS11 = generateMasterSecret_TLS prf_MD5SHA1
generateMasterSecret TLS12 = generateMasterSecret_TLS prf_SHA256

generateKeyBlock_TLS :: PRF -> ClientRandom -> ServerRandom -> Bytes -> Int -> Bytes
generateKeyBlock_TLS prf (ClientRandom c) (ServerRandom s) mastersecret kbsize =
        prf mastersecret seed kbsize where seed = B.concat [ "key expansion", s, c ]

generateKeyBlock_SSL :: ClientRandom -> ServerRandom -> Bytes -> Int -> Bytes
generateKeyBlock_SSL (ClientRandom c) (ServerRandom s) mastersecret kbsize =
        B.concat $ map computeMD5 $ take ((kbsize `div` 16) + 1) labels
        where
                labels            = [ uncurry BC.replicate x | x <- zip [1..] ['A'..'Z'] ]
                computeMD5  label = MD5.hash $ B.concat [ mastersecret, computeSHA1 label ]
                computeSHA1 label = SHA1.hash $ B.concat [ label, mastersecret, s, c ]

generateKeyBlock :: Version -> ClientRandom -> ServerRandom -> Bytes -> Int -> Bytes
generateKeyBlock SSL2  = generateKeyBlock_SSL
generateKeyBlock SSL3  = generateKeyBlock_SSL
generateKeyBlock TLS10 = generateKeyBlock_TLS prf_MD5SHA1
generateKeyBlock TLS11 = generateKeyBlock_TLS prf_MD5SHA1
generateKeyBlock TLS12 = generateKeyBlock_TLS prf_SHA256

generateFinished_TLS :: PRF -> Bytes -> Bytes -> HashCtx -> Bytes
generateFinished_TLS prf label mastersecret hashctx = prf mastersecret seed 12
        where
                seed = B.concat [ label, hashFinal hashctx ]

generateFinished_SSL :: Bytes -> Bytes -> HashCtx -> Bytes
generateFinished_SSL sender mastersecret hashctx = B.concat [md5hash, sha1hash]
        where
                md5hash  = MD5.hash $ B.concat [ mastersecret, pad2, md5left ]
                sha1hash = SHA1.hash $ B.concat [ mastersecret, B.take 40 pad2, sha1left ]

                lefthash = hashFinal $ flip hashUpdateSSL (pad1, B.take 40 pad1)
                                     $ foldl hashUpdate hashctx [sender,mastersecret]
                (md5left,sha1left) = B.splitAt 16 lefthash
                pad2     = B.replicate 48 0x5c
                pad1     = B.replicate 48 0x36

generateClientFinished :: Version -> Bytes -> HashCtx -> Bytes
generateClientFinished ver
        | ver < TLS10 = generateFinished_SSL "CLNT"
        | ver < TLS12 = generateFinished_TLS prf_MD5SHA1 "client finished"
        | otherwise   = generateFinished_TLS prf_SHA256 "client finished"

generateServerFinished :: Version -> Bytes -> HashCtx -> Bytes
generateServerFinished ver
        | ver < TLS10 = generateFinished_SSL "SRVR"
        | ver < TLS12 = generateFinished_TLS prf_MD5SHA1 "server finished"
        | otherwise   = generateFinished_TLS prf_SHA256 "server finished"

generateCertificateVerify_SSL :: Bytes -> HashCtx -> Bytes
generateCertificateVerify_SSL = generateFinished_SSL ""
