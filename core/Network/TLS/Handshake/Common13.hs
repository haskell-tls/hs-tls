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
       , createTLS13TicketInfo
       , ageToObfuscatedAge
       , isAgeValid
       , getAge
       , checkFreshness
       , getCurrentTimeFromBase
       , getSessionData13
       , safeNonNegative32
       , RecvHandshake13M
       , runRecvHandshake13
       , recvHandshake13preUpdate
       , recvHandshake13postUpdate
       ) where

import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import Data.Hourglass
import Network.TLS.Context.Internal
import Network.TLS.Cipher
import Network.TLS.Crypto
import qualified Network.TLS.Crypto.IES as IES
import Network.TLS.Extension
import Network.TLS.Handshake.Process (processHandshake13)
import Network.TLS.Handshake.Common (unexpected)
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.Handshake.Signature
import Network.TLS.Imports
import Network.TLS.KeySchedule
import Network.TLS.MAC
import Network.TLS.IO
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types
import Network.TLS.Wire
import Network.TLS.Util
import Time.System

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
  Left  e    -> throwCore $ Error_Protocol (show e, True, HandshakeFailure)
  Right cpub -> do
      (spub, share) <- fromJust "ECDHEShared" <$> generateECDHEShared ctx cpub
      let wspub = IES.encodeGroupPublic spub
          serverKeyShare = KeyShareEntry grp wspub
          key = BA.convert share
      return (key, serverKeyShare)
  where
    ecpub = IES.decodeGroupPublic grp wcpub

makeClientKeyShare :: Context -> Group -> IO (IES.GroupPrivate, KeyShareEntry)
makeClientKeyShare ctx grp = do
    (cpri, cpub) <- generateECDHE ctx grp
    let wcpub = IES.encodeGroupPublic cpub
        clientKeyShare = KeyShareEntry grp wcpub
    return (cpri, clientKeyShare)

fromServerKeyShare :: KeyShareEntry -> IES.GroupPrivate -> IO ByteString
fromServerKeyShare (KeyShareEntry grp wspub) cpri = case espub of
  Left  e    -> throwCore $ Error_Protocol (show e, True, HandshakeFailure)
  Right spub -> case IES.groupGetShared spub cpri of
    Just shared -> return $ BA.convert shared
    Nothing     -> throwCore $ Error_Protocol ("cannote generate a shared secret on (EC)DH", True, HandshakeFailure)
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

createTLS13TicketInfo :: Second -> Either Context Second -> Maybe Millisecond -> IO TLS13TicketInfo
createTLS13TicketInfo life ecw mrtt = do
    -- Left:  serverSendTime
    -- Right: clientReceiveTime
    bTime <- getCurrentTimeFromBase
    add <- case ecw of
        Left ctx -> B.foldl' (*+) 0 <$> usingState_ ctx (genRandom 4)
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

recvHandshake13preUpdate :: MonadIO m
                         => Context
                         -> (Handshake13 -> RecvHandshake13M m a)
                         -> RecvHandshake13M m a
recvHandshake13preUpdate ctx f = do
    h <- getHandshake13 ctx
    liftIO $ processHandshake13 ctx h
    f h

recvHandshake13postUpdate :: MonadIO m
                          => Context
                          -> (Handshake13 -> RecvHandshake13M m a)
                          -> RecvHandshake13M m a
recvHandshake13postUpdate ctx f = do
    h <- getHandshake13 ctx
    v <- f h
    liftIO $ processHandshake13 ctx h
    return v

getHandshake13 :: MonadIO m => Context -> RecvHandshake13M m Handshake13
getHandshake13 ctx = RecvHandshake13M $ do
    currentState <- get
    case currentState of
        (h:hs) -> found h hs
        []     -> recvLoop
  where
    found h hs = put hs >> return h
    recvLoop = do
        epkt <- recvPacket13 ctx
        case epkt of
            Right (Handshake13 [])     -> recvLoop
            Right (Handshake13 (h:hs)) -> found h hs
            Right ChangeCipherSpec13   -> recvLoop
            Right x                    -> unexpected (show x) (Just "handshake 13")
            Left err                   -> throwCore err

runRecvHandshake13 :: MonadIO m => RecvHandshake13M m a -> m a
runRecvHandshake13 (RecvHandshake13M f) = do
    (result, new) <- runStateT f []
    unless (null new) $ unexpected "spurious handshake 13" Nothing
    return result
