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
	-- * marshall functions for header messages
	  decodeHeader
	, encodeHeader

	-- * marshall functions for alert messages
	, decodeAlert
	, encodeAlert

	-- * marshall functions for handshake messages
	, decodeHandshakeHeader
	, decodeHandshake
	, encodeHandshake
	, encodeHandshakeHeader
	, encodeHandshakeContent

	-- * marshall functions for change cipher spec message
	, decodeChangeCipherSpec
	, encodeChangeCipherSpec

	-- * generate things for packet content
	, generateMasterSecret
	, generateKeyBlock
	, generateClientFinished
	, generateServerFinished
	) where

import Data.Word
import Network.TLS.Wire
import Data.Either (partitionEithers)
import Data.Maybe (fromJust, isNothing)
import Control.Monad
import Control.Monad.Error
import Network.TLS.Struct
import Data.Certificate.X509
import Network.TLS.Crypto
import Network.TLS.MAC
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as L (pack, length, concat, fromChunks)
import qualified Data.ByteString as B

{-
 - decode and encode headers
 -}
decodeHeader :: ByteString -> Either TLSError Header
decodeHeader = runGet $ do
	ty <- getWord8
	major <- getWord8
	minor <- getWord8
	len <- getWord16
	case (valToType ty, verOfNum (major, minor)) of
		(Just y, Just v) -> return $ Header y v len
		(Nothing, _)     -> throwError (Error_Packet "invalid type")
		(_, Nothing)     -> throwError (Error_Packet "invalid version")

encodeHeader :: Header -> ByteString
encodeHeader (Header pt ver len) =
	{- FIXME check len <= 2^14 -}
	runPut (putWord8 (valOfType pt) >> putWord8 major >> putWord8 minor >> putWord16 len)
	where (major, minor) = numericalVer ver

{-
 - decode and encode ALERT
 -}

decodeAlert :: ByteString -> Either TLSError (AlertLevel, AlertDescription)
decodeAlert = runGet $ do
	al <- getWord8
	ad <- getWord8
	case (valToType al, valToType ad) of
		(Just a, Just d) -> return (a, d)
		(Nothing, _)     -> throwError (Error_Packet "missing alert level")
		(_, Nothing)     -> throwError (Error_Packet "missing alert description")

encodeAlert :: (AlertLevel, AlertDescription) -> ByteString
encodeAlert (al, ad) = runPut (putWord8 (valOfType al) >> putWord8 (valOfType ad))

{- decode and encode HANDSHAKE -}

decodeHandshakeHeader :: ByteString -> Either TLSError (HandshakeType, ByteString)
decodeHandshakeHeader = runGet $ do
	tyopt <- getWord8 >>= return . valToType
	ty <- if isNothing tyopt
		then throwError (Error_Unknown_Type "handshake type")
		else return $ fromJust tyopt
	len <- getWord24
	content <- getBytes len
	empty <- isEmpty
	unless empty (throwError (Error_Internal_Packet_Remaining 1))
	return (ty, L.fromChunks [content])

decodeHandshake :: Version -> HandshakeType -> ByteString -> Either TLSError Handshake
decodeHandshake ver ty = runGet $ case ty of
	HandshakeType_HelloRequest    -> decodeHelloRequest
	HandshakeType_ClientHello     -> decodeClientHello
	HandshakeType_ServerHello     -> decodeServerHello
	HandshakeType_Certificate     -> decodeCertificates
	HandshakeType_ServerKeyXchg   -> decodeServerKeyXchg ver
	HandshakeType_CertRequest     -> decodeCertRequest ver
	HandshakeType_ServerHelloDone -> decodeServerHelloDone
	HandshakeType_CertVerify      -> decodeCertVerify
	HandshakeType_ClientKeyXchg   -> decodeClientKeyXchg
	HandshakeType_Finished        -> decodeFinished ver

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
	exts <- if ver >= TLS12 && r > 0
		then fmap fromIntegral getWord16 >>= getExtensions >>= return . Just
		else return Nothing
	return $ ClientHello ver random session ciphers compressions exts

decodeServerHello :: Get Handshake
decodeServerHello = do
	ver           <- getVersion
	random        <- getServerRandom32
	session       <- getSession
	cipherid      <- getWord16
	compressionid <- getWord8
	r             <- remaining
	exts <- if ver >= TLS12 && r > 0
		then fmap fromIntegral getWord16 >>= getExtensions >>= return . Just
		else return Nothing
	return $ ServerHello ver random session cipherid compressionid exts

decodeServerHelloDone :: Get Handshake
decodeServerHelloDone = return ServerHelloDone

decodeCertificates :: Get Handshake
decodeCertificates = do
	certslen <- getWord24
	certs <- getCerts certslen >>= return . map (decodeCertificate . L.fromChunks . (:[]))
	let (l, r) = partitionEithers certs
	if length l > 0
		then throwError $ Error_Certificate $ show l
		else return $ Certificates r

decodeFinished :: Version -> Get Handshake
decodeFinished ver = do
	-- unfortunately passing the verify_data_size here would be tedious for >=TLS12,
	-- so just return the remaining string.
	len <- if ver >= TLS12
		then remaining
		else return 12
	opaque <- getBytes (fromIntegral len)
	return $ Finished $ B.unpack opaque

getSignatureHashAlgorithm :: Int -> Get [ (HashAlgorithm, SignatureAlgorithm) ]
getSignatureHashAlgorithm 0   = return []
getSignatureHashAlgorithm len = do
	h <- fmap (fromJust . valToType) getWord8
	s <- fmap (fromJust . valToType) getWord8
	xs <- getSignatureHashAlgorithm (len - 2)
	return ((h, s) : xs)

decodeCertRequest :: Version -> Get Handshake
decodeCertRequest ver = do
	certTypes <- fmap (map (fromJust . valToType . fromIntegral)) getWords8

	sigHashAlgs <- if ver >= TLS12
		then do
			sighashlen <- getWord16
			fmap Just $ getSignatureHashAlgorithm $ fromIntegral sighashlen
		else return Nothing
	dNameLen <- getWord16
	when (ver < TLS12 && dNameLen < 3) $ throwError (Error_Misc "certrequest distinguishname not of the correct size")
	dName <- getBytes $ fromIntegral dNameLen
	return $ CertRequest certTypes sigHashAlgs (B.unpack dName)

decodeCertVerify :: Get Handshake
decodeCertVerify =
	{- FIXME -}
	return $ CertVerify []

decodeClientKeyXchg :: Get Handshake
decodeClientKeyXchg = do
	ver <- getVersion
	ran <- getClientKeyData46
	return $ ClientKeyXchg ver ran

-- FIXME need to work out how we marshall an opaque number
--numberise :: ByteString -> Integer
numberise _ = 0

decodeServerKeyXchg_DH :: Get ServerDHParams
decodeServerKeyXchg_DH = do
	p <- getWord16 >>= getBytes . fromIntegral
	g <- getWord16 >>= getBytes . fromIntegral
	y <- getWord16 >>= getBytes . fromIntegral
	return $ ServerDHParams { dh_p = numberise p, dh_g = numberise g, dh_Ys = numberise y }

decodeServerKeyXchg_RSA :: Get ServerRSAParams
decodeServerKeyXchg_RSA = do
	modulus <- getWord16 >>= getBytes . fromIntegral
	expo <- getWord16 >>= getBytes . fromIntegral
	return $ ServerRSAParams { rsa_modulus = numberise modulus, rsa_exponent = numberise expo }

decodeServerKeyXchg :: Version -> Get Handshake
decodeServerKeyXchg ver = do
	-- mostly unimplemented
	skxAlg <- case ver of
		TLS12 -> return $ SKX_RSA Nothing
		TLS10 -> do
			rsaparams <- decodeServerKeyXchg_RSA
			return $ SKX_RSA $ Just rsaparams
		_ -> do
			return $ SKX_RSA Nothing
	return (ServerKeyXchg skxAlg)

encodeHandshake :: Handshake -> ByteString
encodeHandshake o =
	let content = runPut $ encodeHandshakeContent o in
	let len = fromIntegral $ L.length content in
	let header = runPut $ encodeHandshakeHeader (typeOfHandshake o) len in
	L.concat [ header, content ]

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

encodeHandshakeContent (Certificates certs) =
	putWord24 len >> putLazyByteString certbs
	where
		certbs = runPut $ mapM_ putCert certs
		len    = fromIntegral $ L.length certbs

encodeHandshakeContent (ClientKeyXchg version random) = do
	putVersion version
	putClientKeyData46 random

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
	putByteString $ B.pack certAuthorities

encodeHandshakeContent (CertVerify _) = undefined

encodeHandshakeContent (Finished opaque) = mapM_ putWord8 opaque

{- marshall helpers -}
getVersion :: Get Version
getVersion = do
	major <- getWord8
	minor <- getWord8
	case verOfNum (major, minor) of
		Just v   -> return v
		Nothing  -> throwError (Error_Unknown_Version major minor)

putVersion :: Version -> Put
putVersion ver = putWord8 major >> putWord8 minor
	where (major, minor) = numericalVer ver

{- FIXME make sure it return error if not 32 available -}
getRandom32 :: Get [Word8]
getRandom32 = fmap B.unpack $ getBytes 32

getServerRandom32 :: Get ServerRandom
getServerRandom32 = fmap ServerRandom getRandom32

getClientRandom32 :: Get ClientRandom
getClientRandom32 = fmap ClientRandom getRandom32

putRandom32 :: [Word8] -> Put
putRandom32 = mapM_ putWord8

putClientRandom32 :: ClientRandom -> Put
putClientRandom32 (ClientRandom r) = putRandom32 r

putServerRandom32 :: ServerRandom -> Put
putServerRandom32 (ServerRandom r) = putRandom32 r

getClientKeyData46 :: Get ClientKeyData
getClientKeyData46 = (ClientKeyData . B.unpack) `fmap` getBytes 46

putClientKeyData46 :: ClientKeyData -> Put
putClientKeyData46 (ClientKeyData d) = mapM_ putWord8 d

getSession :: Get Session
getSession = do
	len8 <- getWord8
	case fromIntegral len8 of
		0   -> return $ Session Nothing
		len -> fmap (Session . Just . B.unpack) $ getBytes len

putSession :: Session -> Put
putSession (Session session) =
	case session of
		Nothing -> putWord8 0
		Just s  -> putWord8 (fromIntegral $ length s) >> mapM_ putWord8 s

getCerts :: Int -> Get [B.ByteString]
getCerts 0   = return []
getCerts len = do
	certlen <- getWord24
	cert <- getBytes certlen
	certxs <- getCerts (len - certlen - 3)
	return (cert : certxs)

putCert :: Certificate -> Put
putCert cert = putWord24 (fromIntegral $ L.length content) >> putLazyByteString content
	where content = encodeCertificate cert

getExtensions :: Int -> Get [Extension]
getExtensions 0   = return []
getExtensions len = do
	extty <- getWord16
	extdatalen <- getWord16
	extdata <- getBytes $ fromIntegral extdatalen
	extxs <- getExtensions (len - fromIntegral extdatalen - 4)
	return $ (extty, B.unpack extdata) : extxs

putExtension :: Extension -> Put
putExtension (ty, l) = do
	putWord16 ty
	putWord16 (fromIntegral $ length l)
	putByteString (B.pack l)

putExtensions :: Maybe [Extension] -> Put
putExtensions Nothing   = return ()
putExtensions (Just es) =
	putWord16 (fromIntegral $ L.length extbs) >> putLazyByteString extbs
	where
		extbs = runPut $ mapM_ putExtension es

{-
 - decode and encode ALERT
 -}

decodeChangeCipherSpec :: ByteString -> Either TLSError ()
decodeChangeCipherSpec b = do
	x <- runGet getWord8 b
	if x == 1 then Right () else Left $ Error_Misc "unknown change cipher spec content"

encodeChangeCipherSpec :: ByteString
encodeChangeCipherSpec = runPut (putWord8 1)

{-
 - generate things for packet content
 -}
generateMasterSecret :: ByteString -> ClientRandom -> ServerRandom -> ByteString
generateMasterSecret premasterSecret (ClientRandom c) (ServerRandom s) =
	prf_MD5SHA1 premasterSecret seed 48
	where
		label = map (toEnum . fromEnum) "master secret"
		seed = L.concat $ map L.pack [ label, c, s]

generateKeyBlock :: ClientRandom -> ServerRandom -> ByteString -> Int -> ByteString
generateKeyBlock (ClientRandom c) (ServerRandom s) mastersecret kbsize =
	prf_MD5SHA1 mastersecret seed kbsize
	where
		label = map (toEnum . fromEnum) "key expansion"
		seed = L.concat $ map L.pack [ label, s, c ]

generateFinished :: String -> ByteString -> HashCtx -> HashCtx -> ByteString
generateFinished label mastersecret md5ctx sha1ctx =
	prf_MD5SHA1 mastersecret seed 12
	where
		plabel = B.pack $ map (toEnum . fromEnum) label
		seed = L.fromChunks [ plabel, finalizeHash md5ctx, finalizeHash sha1ctx ]

generateClientFinished :: ByteString -> HashCtx -> HashCtx -> ByteString
generateClientFinished = generateFinished "client finished"

generateServerFinished :: ByteString -> HashCtx -> HashCtx -> ByteString
generateServerFinished = generateFinished "server finished"
