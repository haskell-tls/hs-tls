{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Packet13 (
    encodeHandshake13,
    decodeHandshakeRecord13,
    decodeHandshake13,
    decodeHandshakes13,
    encodeCertificate13,
) where

import Codec.Compression.Zlib
import qualified Control.Exception as E
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import Data.X509 (
    CertificateChain,
    CertificateChainRaw (..),
    decodeCertificateChain,
    encodeCertificateChain,
 )
import Network.TLS.ErrT
import Network.TLS.Imports
import Network.TLS.Packet
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types
import Network.TLS.Wire
import System.IO.Unsafe

----------------------------------------------------------------

encodeHandshake13 :: Handshake13 -> ByteString
encodeHandshake13 hdsk = pkt
  where
    tp = typeOfHandshake13 hdsk
    content = encodeHandshake13' hdsk
    len = B.length content
    header = encodeHandshakeHeader13 tp len
    pkt = B.concat [header, content]

-- TLS 1.3 does not use "select (extensions_present)".
putExtensions :: [ExtensionRaw] -> Put
putExtensions es = putOpaque16 (runPut $ mapM_ putExtension es)

encodeHandshake13' :: Handshake13 -> ByteString
encodeHandshake13' (ServerHello13 random session cipherId exts) = runPut $ do
    putBinaryVersion TLS12
    putServerRandom32 random
    putSession session
    putWord16 $ fromCipherId cipherId
    putWord8 0 -- compressionID nullCompression
    putExtensions exts
encodeHandshake13' (NewSessionTicket13 life ageadd nonce label exts) = runPut $ do
    putWord32 life
    putWord32 ageadd
    putOpaque8 nonce
    putOpaque16 label
    putExtensions exts
encodeHandshake13' EndOfEarlyData13 = ""
encodeHandshake13' (EncryptedExtensions13 exts) = runPut $ putExtensions exts
encodeHandshake13' (Certificate13 reqctx (TLSCertificateChain cc) ess) = encodeCertificate13 reqctx cc ess
encodeHandshake13' (CertRequest13 reqctx exts) = runPut $ do
    putOpaque8 reqctx
    putExtensions exts
encodeHandshake13' (CertVerify13 (DigitallySigned hs sig)) = runPut $ do
    putSignatureHashAlgorithm hs
    putOpaque16 sig
encodeHandshake13' (Finished13 (VerifyData dat)) = runPut $ putBytes dat
encodeHandshake13' (KeyUpdate13 UpdateNotRequested) = runPut $ putWord8 0
encodeHandshake13' (KeyUpdate13 UpdateRequested) = runPut $ putWord8 1
encodeHandshake13' (CompressedCertificate13 reqctx (TLSCertificateChain cc) ess) = runPut $ do
    putWord16 1 -- zlib: fixme
    let bs = encodeCertificate13 reqctx cc ess
    putWord24 $ fromIntegral $ B.length bs
    putOpaque24 $ BL.toStrict $ compress $ BL.fromStrict bs

encodeHandshakeHeader13 :: HandshakeType -> Int -> ByteString
encodeHandshakeHeader13 ty len = runPut $ do
    putWord8 (fromHandshakeType ty)
    putWord24 len

encodeCertificate13
    :: CertReqContext -> CertificateChain -> [[ExtensionRaw]] -> ByteString
encodeCertificate13 reqctx cc ess = runPut $ do
    putOpaque8 reqctx
    putOpaque24 (runPut $ mapM_ putCert $ zip certs ess)
  where
    CertificateChainRaw certs = encodeCertificateChain cc
    putCert (certRaw, exts) = do
        putOpaque24 certRaw
        putExtensions exts

----------------------------------------------------------------

decodeHandshakes13 :: MonadError TLSError m => ByteString -> m [Handshake13]
decodeHandshakes13 bs = case decodeHandshakeRecord13 bs of
    GotError err -> throwError err
    GotPartial _cont -> error "decodeHandshakes13"
    GotSuccess (ty, content) -> case decodeHandshake13 ty content of
        Left e -> throwError e
        Right h -> return [h]
    GotSuccessRemaining (ty, content) left -> case decodeHandshake13 ty content of
        Left e -> throwError e
        Right h -> (h :) <$> decodeHandshakes13 left

decodeHandshakeRecord13 :: ByteString -> GetResult (HandshakeType, ByteString)
decodeHandshakeRecord13 = runGet "handshake-record" $ do
    ty <- getHandshakeType
    content <- getOpaque24
    return (ty, content)

{- FOURMOLU_DISABLE -}
decodeHandshake13
    :: HandshakeType -> ByteString -> Either TLSError Handshake13
decodeHandshake13 ty = runGetErr ("handshake[" ++ show ty ++ "]") $ case ty of
    HandshakeType_ServerHello           -> decodeServerHello13
    HandshakeType_NewSessionTicket      -> decodeNewSessionTicket13
    HandshakeType_EndOfEarlyData        -> return EndOfEarlyData13
    HandshakeType_EncryptedExtensions   -> decodeEncryptedExtensions13
    HandshakeType_Certificate           -> decodeCertificate13
    HandshakeType_CertRequest           -> decodeCertRequest13
    HandshakeType_CertVerify            -> decodeCertVerify13
    HandshakeType_Finished              -> decodeFinished13
    HandshakeType_KeyUpdate             -> decodeKeyUpdate13
    HandshakeType_CompressedCertificate -> decodeCompressedCertificate13
    (HandshakeType x) -> fail $ "Unsupported HandshakeType " ++ show x
{- FOURMOLU_ENABLE -}

decodeServerHello13 :: Get Handshake13
decodeServerHello13 = do
    _ver <- getBinaryVersion
    random <- getServerRandom32
    session <- getSession
    cipherid <- CipherId <$> getWord16
    _comp <- getWord8
    exts <- fromIntegral <$> getWord16 >>= getExtensions
    return $ ServerHello13 random session cipherid exts

decodeNewSessionTicket13 :: Get Handshake13
decodeNewSessionTicket13 = do
    life <- getWord32
    ageadd <- getWord32
    nonce <- getOpaque8
    label <- getOpaque16
    len <- fromIntegral <$> getWord16
    exts <- getExtensions len
    return $ NewSessionTicket13 life ageadd nonce label exts

decodeEncryptedExtensions13 :: Get Handshake13
decodeEncryptedExtensions13 =
    EncryptedExtensions13 <$> do
        len <- fromIntegral <$> getWord16
        getExtensions len

decodeCertificate13 :: Get Handshake13
decodeCertificate13 = do
    reqctx <- getOpaque8
    len <- fromIntegral <$> getWord24
    (certRaws, ess) <- unzip <$> getList len getCert
    case decodeCertificateChain $ CertificateChainRaw certRaws of
        Left (i, s) -> fail ("error certificate parsing " ++ show i ++ ":" ++ s)
        Right cc -> return $ Certificate13 reqctx (TLSCertificateChain cc) ess
  where
    getCert = do
        l <- fromIntegral <$> getWord24
        cert <- getBytes l
        len <- fromIntegral <$> getWord16
        exts <- getExtensions len
        return (3 + l + 2 + len, (cert, exts))

decodeCertRequest13 :: Get Handshake13
decodeCertRequest13 = do
    reqctx <- getOpaque8
    len <- fromIntegral <$> getWord16
    exts <- getExtensions len
    return $ CertRequest13 reqctx exts

decodeCertVerify13 :: Get Handshake13
decodeCertVerify13 =
    CertVerify13 <$> (DigitallySigned <$> getSignatureHashAlgorithm <*> getOpaque16)

decodeFinished13 :: Get Handshake13
decodeFinished13 = Finished13 . VerifyData <$> (remaining >>= getBytes)

decodeKeyUpdate13 :: Get Handshake13
decodeKeyUpdate13 = do
    ru <- getWord8
    case ru of
        0 -> return $ KeyUpdate13 UpdateNotRequested
        1 -> return $ KeyUpdate13 UpdateRequested
        x -> fail $ "Unknown request_update: " ++ show x

decodeCompressedCertificate13 :: Get Handshake13
decodeCompressedCertificate13 = do
    algo <- getWord16
    when (algo /= 1) $ fail "comp algo is not supported" -- fixme
    len <- getWord24
    bs <- getOpaque24
    if bs == ""
        then fail "empty compressed certificate"
        else case decompressIt bs of
            Left e -> fail (show e)
            Right bs' -> do
                when (B.length bs' /= len) $ fail "plain length is wrong"
                case runGetMaybe decodeCertificate13 bs' of
                    Just (Certificate13 reqctx certs ess) -> return $ CompressedCertificate13 reqctx certs ess
                    --                    _ -> fail "compressed certificate cannot be parsed"
                    _ -> fail $ "invalid compressed certificate: len = " ++ show len

decompressIt :: ByteString -> Either DecompressError ByteString
decompressIt inp = unsafePerformIO $ E.handle handler $ do
    Right . BL.toStrict <$> E.evaluate (decompress (BL.fromStrict inp))
  where
    handler e = return $ Left (e :: DecompressError)
