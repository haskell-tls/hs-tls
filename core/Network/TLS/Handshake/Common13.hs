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
       , ensureNullCompression
       , isHashSignatureValid13
       , safeNonNegative32
       , RecvHandshake13M
       , runRecvHandshake13
       , runRecvHandshake13'
       , recvHandshake13
       , recvHandshake13'
       , pushbackHandshake13
       , Choice(..)
       , makeChoice
       , calcEarlySecret
       , calculateEarlySecret
       , calculateHandshakeSecret
       , calculateTrafficSecret
       , calculateResumptionSecret
       , calcPSK
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
      ecdhePair <- generateECDHEShared ctx cpub
      case ecdhePair of
          Nothing -> throwCore $ Error_Protocol (msgInvalidPublic, True, HandshakeFailure)
          Just (spub, share) ->
              let wspub = IES.encodeGroupPublic spub
                  serverKeyShare = KeyShareEntry grp wspub
               in return (BA.convert share, serverKeyShare)
  where
    ecpub = IES.decodeGroupPublic grp wcpub
    msgInvalidPublic = "invalid server " ++ show grp ++ " public key"

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
    Nothing     -> throwCore $ Error_Protocol ("cannot generate a shared secret on (EC)DH", True, HandshakeFailure)
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

makePSKBinder :: Context -> Secret13 -> Hash -> Int -> Maybe ByteString -> IO ByteString
makePSKBinder ctx (EarlySecret sec) usedHash truncLen mch = do
    rmsgs0 <- usingHState ctx getHandshakeMessagesRev -- fixme
    let rmsgs = case mch of
          Just ch -> trunc ch : rmsgs0
          Nothing -> trunc (head rmsgs0) : tail rmsgs0
        hChTruncated = hash usedHash $ B.concat $ reverse rmsgs
        binderKey = deriveSecret usedHash sec "res binder" (hash usedHash "")
    return $ makeVerifyData usedHash binderKey hChTruncated
  where
    trunc x = B.take takeLen x
      where
        totalLen = B.length x
        takeLen = totalLen - truncLen
makePSKBinder _ _ _ _ _ = error "makePSKBinder"

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
recvHandshake13 ctx f = do
    h <- getHandshake13 ctx
    v <- f h
    newhs <- RecvHandshake13M $ get
    case newhs of
      []            -> liftIO $ processHandshake13 ctx h
      newh:_
        | h == newh -> return () -- push backed
        | otherwise -> liftIO $ processHandshake13 ctx h
    return v

recvHandshake13' :: MonadIO m
                 => Context
                 -> (Handshake13 -> RecvHandshake13M m a)
                 -> RecvHandshake13M m a
recvHandshake13' ctx f = do
    h <- getHS
    v <- f h
    newbss <- RecvHandshake13M $ get
    case newbss of
      []            -> liftIO $ processHandshake13 ctx h
      newh:_
        | h == newh -> return () -- push backed
        | otherwise -> liftIO $ processHandshake13 ctx h
    return v
  where
    getHS = RecvHandshake13M $ do
        current <- get
        case current of
          []     -> error "getHS"
          h:hs -> do
              put hs
              return h

pushbackHandshake13 :: Monad m => Handshake13 -> RecvHandshake13M m ()
pushbackHandshake13 h = RecvHandshake13M $ do
    hs <- get
    put (h:hs)

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

runRecvHandshake13' :: MonadIO m => [Handshake13] -> RecvHandshake13M m a -> m a
runRecvHandshake13' hss (RecvHandshake13M f) = do
    (result, new) <- runStateT f hss
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

data Choice = Choice {
    cVersion :: Version
  , cCipher  :: Cipher
  , cHash    :: Hash
  , cZero    :: !ByteString
  }

makeChoice :: Version -> Cipher -> Choice
makeChoice ver cipher = Choice ver cipher h zero
  where
    h = cipherHash cipher
    zero = B.replicate (hashDigestSize h) 0

calculateEarlySecret :: Context -> Choice
                     -> Either ByteString Secret13
                     -> Bool -> IO SecretTriple
calculateEarlySecret ctx choice maux initialized = do
    hCh <- if initialized then
               transcriptHash ctx
             else do
               hmsgs <- usingHState ctx getHandshakeMessages
               return $ hash usedHash $ B.concat hmsgs
    let earlySecret = case maux of
          Right (EarlySecret sec) -> sec
          Right _                 -> error "calculateEarlySecret"
          Left  psk               -> hkdfExtract usedHash zero psk
        clientEarlySecret = deriveSecret usedHash earlySecret "c e traffic" hCh
        cets = ClientEarlySecret clientEarlySecret
    logKey ctx cets
    return $ SecretTriple (EarlySecret earlySecret) cets cets {- dummy -}
  where
    usedHash = cHash choice
    zero = cZero choice

calcEarlySecret :: Choice -> Maybe ByteString -> Secret13
calcEarlySecret choice mpsk = EarlySecret sec
  where
    sec = hkdfExtract usedHash zero zeroOrPSK
    usedHash = cHash choice
    zero = cZero choice
    zeroOrPSK = case mpsk of
      Just psk -> psk
      Nothing  -> zero

calculateHandshakeSecret :: Context -> Choice -> Secret13 -> ByteString
                         -> IO SecretTriple
calculateHandshakeSecret ctx choice (EarlySecret sec) ecdhe = do
        hChSh <- transcriptHash ctx
        let handshakeSecret = hkdfExtract usedHash (deriveSecret usedHash sec "derived" (hash usedHash "")) ecdhe
        let clientHandshakeSecret = deriveSecret usedHash handshakeSecret "c hs traffic" hChSh
            serverHandshakeSecret = deriveSecret usedHash handshakeSecret "s hs traffic" hChSh
        let shts = ServerHandshakeSecret serverHandshakeSecret
            chts = ClientHandshakeSecret clientHandshakeSecret
        logKey ctx shts
        logKey ctx chts
        return $ SecretTriple (HandshakeSecret handshakeSecret) chts shts
  where
    usedHash = cHash choice
calculateHandshakeSecret _ _ _ _ = error "calculateHandshakeSecret"

calculateTrafficSecret :: Context -> Choice -> Secret13 -> Maybe ByteString
                       -> IO SecretTriple
calculateTrafficSecret ctx choice (HandshakeSecret sec) mhChSf = do
    hChSf <- case mhChSf of
      Nothing -> transcriptHash ctx
      Just h  -> return h
    let applicationSecret = hkdfExtract usedHash (deriveSecret usedHash sec "derived" (hash usedHash "")) zero
    let clientApplicationSecret0 = deriveSecret usedHash applicationSecret "c ap traffic" hChSf
        serverApplicationSecret0 = deriveSecret usedHash applicationSecret "s ap traffic" hChSf
        exporterMasterSecret = deriveSecret usedHash applicationSecret "exp master" hChSf
    usingState_ ctx $ setExporterMasterSecret exporterMasterSecret
    let sts0 = ServerApplicationSecret0 serverApplicationSecret0
    let cts0 = ClientApplicationSecret0 clientApplicationSecret0
    logKey ctx sts0
    logKey ctx cts0
    return $ SecretTriple (ApplicationSecret applicationSecret) cts0 sts0
  where
    usedHash = cHash choice
    zero = cZero choice
calculateTrafficSecret _ _ _ _ = error "calculateTrafficSecret"

calculateResumptionSecret :: Context -> Choice -> Secret13 -> IO Secret13
calculateResumptionSecret ctx choice (ApplicationSecret sec) = do
    hChCf <- transcriptHash ctx
    let resumptionMasterSecret = deriveSecret usedHash sec "res master" hChCf
    return $ ResumptionSecret resumptionMasterSecret
  where
    usedHash = cHash choice
calculateResumptionSecret _ _ _ = error "calculateResumptionSecret"

calcPSK :: Choice -> Secret13 -> ByteString -> ByteString
calcPSK choice (ResumptionSecret sec) nonce =
    hkdfExpandLabel usedHash sec "resumption" nonce hashSize
  where
    usedHash = cHash choice
    hashSize = hashDigestSize usedHash
calcPSK _ _ _ = error "calcPSK"
