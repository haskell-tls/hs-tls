{-# LANGUAGE OverloadedStrings, GeneralizedNewtypeDeriving, BangPatterns #-}

-- |
-- Module      : Network.TLS.Handshake.Common13
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.Common13
       ( makeFinished
       , makeVerifyData
       , makeServerKeyShare
       , makeClientKeyShare
       , fromServerKeyShare
       , makeCertVerify
       , checkCertVerify
       , makePSKBinder
       , replacePSKBinder
       , sendChangeCipherSpec13
       , handshakeTerminate13
       , makeCertRequest
       , createTLS13TicketInfo
       , ageToObfuscatedAge
       , isAgeValid
       , getAge
       , checkFreshness
       , getCurrentTimeFromBase
       , getSessionData13
       , ensureNullCompression
       , isHashSignatureValid13
       , safeNonNegative32
       , RecvHandshake13M
       , runRecvHandshake13
       , recvHandshake13
       , recvHandshake13hash
       ) where

import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import Data.Hourglass
import Network.TLS.Compression
import Network.TLS.Context.Internal
import Network.TLS.Cipher
import Network.TLS.Crypto
import qualified Network.TLS.Crypto.IES as IES
import Network.TLS.Extension
import Network.TLS.Handshake.Certificate (extractCAname)
import Network.TLS.Handshake.Process (processHandshake13)
import Network.TLS.Handshake.Common (unexpected)
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.Handshake.Signature
import Network.TLS.Imports
import Network.TLS.KeySchedule
import Network.TLS.MAC
import Network.TLS.Parameters
import Network.TLS.IO
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types
import Network.TLS.Wire
import Time.System

import Control.Concurrent.MVar
import Control.Monad.State.Strict

----------------------------------------------------------------

makeFinished :: MonadIO m => Context -> Hash -> ByteString -> m Handshake13
makeFinished ctx usedHash baseKey =
    Finished13 . makeVerifyData usedHash baseKey <$> transcriptHash ctx

makeVerifyData :: Hash -> ByteString -> ByteString -> ByteString
makeVerifyData usedHash baseKey hashValue = hmac usedHash finishedKey hashValue
  where
    hashSize = hashDigestSize usedHash
    finishedKey = hkdfExpandLabel usedHash baseKey "finished" "" hashSize

----------------------------------------------------------------

makeServerKeyShare :: Context -> KeyShareEntry -> IO (ByteString, KeyShareEntry)
makeServerKeyShare ctx (KeyShareEntry grp wcpub) = case ecpub of
  Left  e    -> throwCore $ Error_Protocol (show e, True, IllegalParameter)
  Right cpub -> do
      ecdhePair <- generateECDHEShared ctx cpub
      case ecdhePair of
          Nothing -> throwCore $ Error_Protocol (msgInvalidPublic, True, IllegalParameter)
          Just (spub, share) ->
              let wspub = IES.encodeGroupPublic spub
                  serverKeyShare = KeyShareEntry grp wspub
               in return (BA.convert share, serverKeyShare)
  where
    ecpub = IES.decodeGroupPublic grp wcpub
    msgInvalidPublic = "invalid client " ++ show grp ++ " public key"

makeClientKeyShare :: Context -> Group -> IO (IES.GroupPrivate, KeyShareEntry)
makeClientKeyShare ctx grp = do
    (cpri, cpub) <- generateECDHE ctx grp
    let wcpub = IES.encodeGroupPublic cpub
        clientKeyShare = KeyShareEntry grp wcpub
    return (cpri, clientKeyShare)

fromServerKeyShare :: KeyShareEntry -> IES.GroupPrivate -> IO ByteString
fromServerKeyShare (KeyShareEntry grp wspub) cpri = case espub of
  Left  e    -> throwCore $ Error_Protocol (show e, True, IllegalParameter)
  Right spub -> case IES.groupGetShared spub cpri of
    Just shared -> return $ BA.convert shared
    Nothing     -> throwCore $ Error_Protocol ("cannot generate a shared secret on (EC)DH", True, IllegalParameter)
  where
    espub = IES.decodeGroupPublic grp wspub

----------------------------------------------------------------

serverContextString :: ByteString
serverContextString = "TLS 1.3, server CertificateVerify"

clientContextString :: ByteString
clientContextString = "TLS 1.3, client CertificateVerify"

makeCertVerify :: MonadIO m => Context -> DigitalSignatureAlg -> HashAndSignatureAlgorithm -> ByteString -> m Handshake13
makeCertVerify ctx sig hs hashValue = do
    cc <- liftIO $ usingState_ ctx isClientContext
    let ctxStr | cc == ClientRole = clientContextString
               | otherwise        = serverContextString
        target = makeTarget ctxStr hashValue
    CertVerify13 hs <$> sign ctx sig hs target

checkCertVerify :: MonadIO m => Context -> DigitalSignatureAlg -> HashAndSignatureAlgorithm -> Signature -> ByteString -> m Bool
checkCertVerify ctx sig hs signature hashValue = liftIO $ do
    cc <- usingState_ ctx isClientContext
    let ctxStr | cc == ClientRole = serverContextString -- opposite context
               | otherwise        = clientContextString
        target = makeTarget ctxStr hashValue
        sigParams = signatureParams sig (Just hs)
    checkHashSignatureValid13 hs
    checkSupportedHashSignature ctx (Just hs)
    verifyPublic ctx sigParams target signature

makeTarget :: ByteString -> ByteString -> ByteString
makeTarget contextString hashValue = runPut $ do
    putBytes $ B.replicate 64 32
    putBytes contextString
    putWord8 0
    putBytes hashValue

sign :: MonadIO m => Context -> DigitalSignatureAlg -> HashAndSignatureAlgorithm -> ByteString -> m Signature
sign ctx sig hs target = liftIO $ do
    cc <- usingState_ ctx isClientContext
    let sigParams = signatureParams sig (Just hs)
    signPrivate ctx cc sigParams target

----------------------------------------------------------------

makePSKBinder :: Context -> ByteString -> Hash -> Int -> Maybe ByteString -> IO ByteString
makePSKBinder ctx earlySecret usedHash truncLen mch = do
    rmsgs0 <- usingHState ctx getHandshakeMessagesRev -- fixme
    let rmsgs = case mch of
          Just ch -> trunc ch : rmsgs0
          Nothing -> trunc (head rmsgs0) : tail rmsgs0
        hChTruncated = hash usedHash $ B.concat $ reverse rmsgs
        binderKey = deriveSecret usedHash earlySecret "res binder" (hash usedHash "")
    return $ makeVerifyData usedHash binderKey hChTruncated
  where
    trunc x = B.take takeLen x
      where
        totalLen = B.length x
        takeLen = totalLen - truncLen

replacePSKBinder :: ByteString -> ByteString -> ByteString
replacePSKBinder pskz binder = identities `B.append` binders
  where
    bindersSize = B.length binder + 3
    identities  = B.take (B.length pskz - bindersSize) pskz
    binders     = runPut $ putOpaque16 $ runPut $ putOpaque8 binder

----------------------------------------------------------------

sendChangeCipherSpec13 :: Context -> PacketFlightM ()
sendChangeCipherSpec13 ctx = do
    sent <- usingHState ctx $ do
                b <- getCCS13Sent
                unless b $ setCCS13Sent True
                return b
    unless sent $ loadPacket13 ctx ChangeCipherSpec13

----------------------------------------------------------------

handshakeTerminate13 :: Context -> IO ()
handshakeTerminate13 ctx = do
    -- forget most handshake data
    liftIO $ modifyMVar_ (ctxHandshake ctx) $ \ mhshake ->
        case mhshake of
            Nothing -> return Nothing
            Just hshake ->
                return $ Just (newEmptyHandshake (hstClientVersion hshake) (hstClientRandom hshake))
                    { hstServerRandom = hstServerRandom hshake
                    , hstMasterSecret = hstMasterSecret hshake
                    , hstNegotiatedGroup = hstNegotiatedGroup hshake
                    , hstHandshakeDigest = hstHandshakeDigest hshake
                    , hstTLS13HandshakeMode = hstTLS13HandshakeMode hshake
                    , hstTLS13RTT0Status = hstTLS13RTT0Status hshake
                    , hstTLS13Secret = hstTLS13Secret hshake
                    }
    -- forget handshake data stored in TLS state
    usingState_ ctx $ do
        setTLS13KeyShare Nothing
        setTLS13PreSharedKey Nothing
    -- mark the secure connection up and running.
    setEstablished ctx Established

----------------------------------------------------------------

makeCertRequest :: ServerParams -> Context -> CertReqContext -> Handshake13
makeCertRequest sparams ctx certReqCtx =
    let sigAlgs = extensionEncode $ SignatureAlgorithms $ supportedHashSignatures $ ctxSupported ctx
        caDns = map extractCAname $ serverCACertificates sparams
        caDnsEncoded = extensionEncode $ CertificateAuthorities caDns
        caExtension
            | null caDns = []
            | otherwise  = [ExtensionRaw extensionID_CertificateAuthorities caDnsEncoded]
        crexts = ExtensionRaw extensionID_SignatureAlgorithms sigAlgs : caExtension
     in CertRequest13 certReqCtx crexts

----------------------------------------------------------------

createTLS13TicketInfo :: Second -> Either Context Second -> Maybe Millisecond -> IO TLS13TicketInfo
createTLS13TicketInfo life ecw mrtt = do
    -- Left:  serverSendTime
    -- Right: clientReceiveTime
    bTime <- getCurrentTimeFromBase
    add <- case ecw of
        Left ctx -> B.foldl' (*+) 0 <$> getStateRNG ctx 4
        Right ad -> return ad
    return $ TLS13TicketInfo life add bTime mrtt
  where
    x *+ y = x * 256 + fromIntegral y

ageToObfuscatedAge :: Second -> TLS13TicketInfo -> Second
ageToObfuscatedAge age tinfo = obfage
  where
    !obfage = age + ageAdd tinfo

obfuscatedAgeToAge :: Second -> TLS13TicketInfo -> Second
obfuscatedAgeToAge obfage tinfo = age
  where
    !age = obfage - ageAdd tinfo

isAgeValid :: Second -> TLS13TicketInfo -> Bool
isAgeValid age tinfo = age <= lifetime tinfo * 1000

getAge :: TLS13TicketInfo -> IO Second
getAge tinfo = do
    let clientReceiveTime = txrxTime tinfo
    clientSendTime <- getCurrentTimeFromBase
    return $! fromIntegral (clientSendTime - clientReceiveTime) -- milliseconds

checkFreshness :: TLS13TicketInfo -> Second -> IO Bool
checkFreshness tinfo obfAge = do
    serverReceiveTime <- getCurrentTimeFromBase
    let freshness = if expectedArrivalTime > serverReceiveTime
                    then expectedArrivalTime - serverReceiveTime
                    else serverReceiveTime - expectedArrivalTime
    -- Some implementations round age up to second.
    -- We take max of 2000 and rtt in the case where rtt is too small.
    let tolerance = max 2000 rtt
        isFresh = freshness < tolerance
    return $ isAlive && isFresh
  where
    serverSendTime = txrxTime tinfo
    Just rtt = estimatedRTT tinfo
    age = obfuscatedAgeToAge obfAge tinfo
    expectedArrivalTime = serverSendTime + rtt + fromIntegral age
    isAlive = isAgeValid age tinfo

getCurrentTimeFromBase :: IO Millisecond
getCurrentTimeFromBase = millisecondsFromBase <$> timeCurrentP

millisecondsFromBase :: ElapsedP -> Millisecond
millisecondsFromBase d = fromIntegral ms
  where
    ElapsedP (Elapsed (Seconds s)) (NanoSeconds ns) = d - timeConvert base
    ms = s * 1000 + ns `div` 1000000
    base = Date 2017 January 1

----------------------------------------------------------------

getSessionData13 :: Context -> Cipher -> TLS13TicketInfo -> Int -> ByteString -> IO SessionData
getSessionData13 ctx usedCipher tinfo maxSize psk = do
    ver   <- usingState_ ctx getVersion
    malpn <- usingState_ ctx getNegotiatedProtocol
    sni   <- usingState_ ctx getClientSNI
    mgrp  <- usingHState ctx getNegotiatedGroup
    return SessionData {
        sessionVersion     = ver
      , sessionCipher      = cipherID usedCipher
      , sessionCompression = 0
      , sessionClientSNI   = sni
      , sessionSecret      = psk
      , sessionGroup       = mgrp
      , sessionTicketInfo  = Just tinfo
      , sessionALPN        = malpn
      , sessionMaxEarlyDataSize = maxSize
      }

----------------------------------------------------------------

ensureNullCompression :: MonadIO m => CompressionID -> m ()
ensureNullCompression compression =
    when (compression /= compressionID nullCompression) $
        throwCore $ Error_Protocol ("compression is not allowed in TLS 1.3", True, IllegalParameter)

-- Word32 is used in TLS 1.3 protocol.
-- Int is used for API for Haskell TLS because it is natural.
-- If Int is 64 bits, users can specify bigger number than Word32.
-- If Int is 32 bits, 2^31 or larger may be converted into minus numbers.
safeNonNegative32 :: (Num a, Ord a, FiniteBits a) => a -> a
safeNonNegative32 x
  | x <= 0                = 0
  | finiteBitSize x <= 32 = x
  | otherwise             = x `min` fromIntegral (maxBound :: Word32)
----------------------------------------------------------------

newtype RecvHandshake13M m a = RecvHandshake13M (StateT [Handshake13] m a)
    deriving (Functor, Applicative, Monad, MonadIO)

recvHandshake13 :: MonadIO m
                => Context
                -> (Handshake13 -> RecvHandshake13M m a)
                -> RecvHandshake13M m a
recvHandshake13 ctx f = getHandshake13 ctx >>= f

recvHandshake13hash :: MonadIO m
                    => Context
                    -> (ByteString -> Handshake13 -> RecvHandshake13M m a)
                    -> RecvHandshake13M m a
recvHandshake13hash ctx f = do
    d <- transcriptHash ctx
    getHandshake13 ctx >>= f d

getHandshake13 :: MonadIO m => Context -> RecvHandshake13M m Handshake13
getHandshake13 ctx = RecvHandshake13M $ do
    currentState <- get
    case currentState of
        (h:hs) -> found h hs
        []     -> recvLoop
  where
    found h hs = liftIO (processHandshake13 ctx h) >> put hs >> return h
    recvLoop = do
        epkt <- recvPacket13 ctx
        case epkt of
            Right (Handshake13 [])     -> error "invalid recvPacket13 result"
            Right (Handshake13 (h:hs)) -> found h hs
            Right ChangeCipherSpec13   -> recvLoop
            Right x                    -> unexpected (show x) (Just "handshake 13")
            Left err                   -> throwCore err

runRecvHandshake13 :: MonadIO m => RecvHandshake13M m a -> m a
runRecvHandshake13 (RecvHandshake13M f) = do
    (result, new) <- runStateT f []
    unless (null new) $ unexpected "spurious handshake 13" Nothing
    return result

----------------------------------------------------------------

-- some hash/signature combinations have been deprecated in TLS13 and should
-- not be used
checkHashSignatureValid13 :: HashAndSignatureAlgorithm -> IO ()
checkHashSignatureValid13 hs =
    unless (isHashSignatureValid13 hs) $
        let msg = "invalid TLS13 hash and signature algorithm: " ++ show hs
         in throwCore $ Error_Protocol (msg, True, IllegalParameter)

isHashSignatureValid13 :: HashAndSignatureAlgorithm -> Bool
isHashSignatureValid13 (HashIntrinsic, s) =
    s `elem` [ SignatureRSApssRSAeSHA256
             , SignatureRSApssRSAeSHA384
             , SignatureRSApssRSAeSHA512
             , SignatureEd25519
             , SignatureEd448
             , SignatureRSApsspssSHA256
             , SignatureRSApsspssSHA384
             , SignatureRSApsspssSHA512
             ]
isHashSignatureValid13 (h, SignatureECDSA) =
    h `elem` [ HashSHA256, HashSHA384, HashSHA512 ]
isHashSignatureValid13 _ = False
