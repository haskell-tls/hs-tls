{-# LANGUAGE GeneralizedNewtypeDeriving, FlexibleContexts, MultiParamTypeClasses, ExistentialQuantification, RankNTypes #-}
-- |
-- Module      : Network.TLS.State
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the State module contains calls related to state initialization/manipulation
-- which is use by the Receiving module and the Sending module.
--
module Network.TLS.State
	( TLSState(..)
	, TLSSt
	, runTLSState
	, TLSHandshakeState(..)
	, TLSCryptState(..)
	, TLSMacState(..)
	, TLSStatus(..)
	, HandshakeStatus(..)
	, newTLSState
	, genTLSRandom
	, withTLSRNG
	, assert -- FIXME move somewhere else (Internal.hs ?)
	, updateStatusHs
	, updateStatusCC
	, finishHandshakeTypeMaterial
	, finishHandshakeMaterial
	, makeDigest
	, setMasterSecret
	, setPublicKey
	, setPrivateKey
	, setKeyBlock
	, setVersion
	, setCipher
	, setServerRandom
	, switchTxEncryption
	, switchRxEncryption
	, getCipherKeyExchangeType
	, isClientContext
	, startHandshakeClient
	, updateHandshakeDigest
	, updateHandshakeDigestSplitted
	, getHandshakeDigest
	, endHandshake
	) where

import Data.Word
import Data.List (find)
import Data.Maybe (isNothing)
import Network.TLS.Util
import Network.TLS.Struct
import Network.TLS.Wire
import Network.TLS.Packet
import Network.TLS.Crypto
import Network.TLS.Cipher
import Network.TLS.MAC
import qualified Data.ByteString as B
import Control.Monad
import Control.Monad.State
import Control.Monad.Error
import Crypto.Random

assert :: Monad m => String -> [(String,Bool)] -> m ()
assert fctname list = forM_ list $ \ (name, assumption) -> do
	when assumption $ fail (fctname ++ ": assumption about " ++ name ++ " failed")

data HandshakeStatus =
	  HsStatusClientHello
	| HsStatusServerHello
	| HsStatusServerCertificate
	| HsStatusServerKeyXchg
	| HsStatusServerCertificateReq
	| HsStatusServerHelloDone
	| HsStatusClientCertificate
	| HsStatusClientKeyXchg
	| HsStatusClientCertificateVerify
	| HsStatusClientChangeCipher
	| HsStatusClientFinished
	| HsStatusServerChangeCipher
	deriving (Show,Eq)

data TLSStatus =
	  StatusInit
	| StatusHandshakeReq
	| StatusHandshake HandshakeStatus
	| StatusOk
	deriving (Show,Eq)

data TLSCryptState = TLSCryptState
	{ cstKey        :: !Bytes
	, cstIV         :: !Bytes
	, cstMacSecret  :: !Bytes
	} deriving (Show)

data TLSMacState = TLSMacState
	{ msSequence :: Word64
	} deriving (Show)

data TLSHandshakeState = TLSHandshakeState
	{ hstClientVersion   :: !(Version)
	, hstClientRandom    :: !ClientRandom
	, hstServerRandom    :: !(Maybe ServerRandom)
	, hstMasterSecret    :: !(Maybe Bytes)
	, hstRSAPublicKey    :: !(Maybe PublicKey)
	, hstRSAPrivateKey   :: !(Maybe PrivateKey)
	, hstHandshakeDigest :: Maybe (HashCtx, HashCtx) -- FIXME could be only 1 hash in tls12
	} deriving (Show)

data StateRNG = forall g . CryptoRandomGen g => StateRNG g

instance Show StateRNG where
	show _ = "rng[..]"

data TLSState = TLSState
	{ stClientContext :: Bool
	, stVersion       :: !Version
	, stStatus        :: !TLSStatus
	, stHandshake     :: !(Maybe TLSHandshakeState)
	, stTxEncrypted   :: Bool
	, stRxEncrypted   :: Bool
	, stTxCryptState  :: !(Maybe TLSCryptState)
	, stRxCryptState  :: !(Maybe TLSCryptState)
	, stTxMacState    :: !(Maybe TLSMacState)
	, stRxMacState    :: !(Maybe TLSMacState)
	, stCipher        :: Maybe Cipher
	, stRandomGen     :: StateRNG
	} deriving (Show)

newtype TLSSt a = TLSSt { runTLSSt :: ErrorT TLSError (State TLSState) a }
	deriving (Monad, MonadError TLSError)

instance Functor TLSSt where
	fmap f = TLSSt . fmap f . runTLSSt

instance MonadState TLSState TLSSt where
	put x = TLSSt (lift $ put x)
	get   = TLSSt (lift get)

runTLSState :: TLSSt a -> TLSState -> (Either TLSError a, TLSState)
runTLSState f st = runState (runErrorT (runTLSSt f)) st

newTLSState :: CryptoRandomGen g => g -> TLSState
newTLSState rng = TLSState
	{ stClientContext = False
	, stVersion       = TLS10
	, stStatus        = StatusInit
	, stHandshake     = Nothing
	, stTxEncrypted   = False
	, stRxEncrypted   = False
	, stTxCryptState  = Nothing
	, stRxCryptState  = Nothing
	, stTxMacState    = Nothing
	, stRxMacState    = Nothing
	, stCipher        = Nothing
	, stRandomGen     = StateRNG rng
	}

withTLSRNG :: StateRNG -> (forall g . CryptoRandomGen g => g -> Either e (a,g)) -> Either e (a, StateRNG)
withTLSRNG (StateRNG rng) f = case f rng of
	Left err        -> Left err
	Right (a, rng') -> Right (a, StateRNG rng')

genTLSRandom :: (MonadState TLSState m, MonadError TLSError m) => Int -> m Bytes
genTLSRandom n = do
	st <- get
	case withTLSRNG (stRandomGen st) (genBytes n) of
		Left err            -> throwError $ Error_Random $ show err
		Right (bytes, rng') -> put (st { stRandomGen = rng' }) >> return bytes

makeDigest :: MonadState TLSState m => Bool -> Header -> Bytes -> m Bytes
makeDigest w hdr content = do
	st <- get
	let ver = stVersion st
	let cst = fromJust "crypt state" $ if w then stTxCryptState st else stRxCryptState st
	let ms = fromJust "mac state" $ if w then stTxMacState st else stRxMacState st
	let cipher = fromJust "cipher" $ stCipher st
	let machash = cipherMACHash cipher

	let (macF, msg) =
		if ver < TLS10
			then (macSSL machash, B.concat [ encodeWord64 $ msSequence ms, encodeHeaderNoVer hdr, content ])
			else (hmac machash 64, B.concat [ encodeWord64 $ msSequence ms, encodeHeader hdr, content ])
	let digest = macF (cstMacSecret cst) msg

	let newms = ms { msSequence = (msSequence ms) + 1 }

	modify (\_ -> if w then st { stTxMacState = Just newms } else st { stRxMacState = Just newms })
	return digest

hsStatusTransitionTable :: [ (HandshakeType, TLSStatus, [ TLSStatus ]) ]
hsStatusTransitionTable =
	[ (HandshakeType_HelloRequest, StatusHandshakeReq,
		[ StatusOk ])
	, (HandshakeType_ClientHello, StatusHandshake HsStatusClientHello,
		[ StatusInit, StatusHandshakeReq ])
	, (HandshakeType_ServerHello, StatusHandshake HsStatusServerHello,
		[ StatusHandshake HsStatusClientHello ])
	, (HandshakeType_Certificate, StatusHandshake HsStatusServerCertificate,
		[ StatusHandshake HsStatusServerHello ])
	, (HandshakeType_ServerKeyXchg, StatusHandshake HsStatusServerKeyXchg,
		[ StatusHandshake HsStatusServerHello
		, StatusHandshake HsStatusServerCertificate ])
	, (HandshakeType_CertRequest, StatusHandshake HsStatusServerCertificateReq,
		[ StatusHandshake HsStatusServerHello
		, StatusHandshake HsStatusServerCertificate
		, StatusHandshake HsStatusServerKeyXchg ])
	, (HandshakeType_ServerHelloDone, StatusHandshake HsStatusServerHelloDone,
		[ StatusHandshake HsStatusServerHello
		, StatusHandshake HsStatusServerCertificate
		, StatusHandshake HsStatusServerKeyXchg
		, StatusHandshake HsStatusServerCertificateReq ])
	, (HandshakeType_Certificate, StatusHandshake HsStatusClientCertificate,
		[ StatusHandshake HsStatusServerHelloDone ])
	, (HandshakeType_ClientKeyXchg, StatusHandshake HsStatusClientKeyXchg,
		[ StatusHandshake HsStatusServerHelloDone
		, StatusHandshake HsStatusClientCertificate ])
	, (HandshakeType_CertVerify, StatusHandshake HsStatusClientCertificateVerify,
		[ StatusHandshake HsStatusClientKeyXchg ])
	, (HandshakeType_Finished, StatusHandshake HsStatusClientFinished,
		[ StatusHandshake HsStatusClientChangeCipher ])
	, (HandshakeType_Finished, StatusOk,
		[ StatusHandshake HsStatusServerChangeCipher ])
	]

updateStatus :: MonadState TLSState m => TLSStatus -> m ()
updateStatus x = modify (\st -> st { stStatus = x })

updateStatusHs :: MonadState TLSState m => HandshakeType -> m (Maybe TLSError)
updateStatusHs ty = do
	status <- return . stStatus =<< get
	ns <- return . transition . stStatus =<< get
	case ns of
		Nothing      -> return $ Just $ Error_Packet_unexpected (show status) ("handshake:" ++ show ty)
		Just (_,x,_) -> updateStatus x >> return Nothing
	where
		edgeEq cur (ety, _, aprevs) = ty == ety && (maybe False (const True) $ find (== cur) aprevs)
		transition currentStatus = find (edgeEq currentStatus) hsStatusTransitionTable

updateStatusCC :: MonadState TLSState m => Bool -> m (Maybe TLSError)
updateStatusCC sending = do
	status <- return . stStatus =<< get
	cc     <- isClientContext
	let x = case (cc /= sending, status) of
		(False, StatusHandshake HsStatusClientKeyXchg)           -> Just (StatusHandshake HsStatusClientChangeCipher)
		(False, StatusHandshake HsStatusClientCertificateVerify) -> Just (StatusHandshake HsStatusClientChangeCipher)
		(True, StatusHandshake HsStatusClientFinished)           -> Just (StatusHandshake HsStatusServerChangeCipher)
		_                                                        -> Nothing
	case x of
		Just newstatus -> updateStatus newstatus >> return Nothing
		Nothing        -> return $ Just $ Error_Packet_unexpected (show status) ("Client Context: " ++ show cc)

finishHandshakeTypeMaterial :: HandshakeType -> Bool
finishHandshakeTypeMaterial HandshakeType_ClientHello     = True
finishHandshakeTypeMaterial HandshakeType_ServerHello     = True
finishHandshakeTypeMaterial HandshakeType_Certificate     = True
finishHandshakeTypeMaterial HandshakeType_HelloRequest    = False
finishHandshakeTypeMaterial HandshakeType_ServerHelloDone = True
finishHandshakeTypeMaterial HandshakeType_ClientKeyXchg   = True
finishHandshakeTypeMaterial HandshakeType_ServerKeyXchg   = True
finishHandshakeTypeMaterial HandshakeType_CertRequest     = True
finishHandshakeTypeMaterial HandshakeType_CertVerify      = False
finishHandshakeTypeMaterial HandshakeType_Finished        = True

finishHandshakeMaterial :: Handshake -> Bool
finishHandshakeMaterial = finishHandshakeTypeMaterial . typeOfHandshake

switchTxEncryption, switchRxEncryption :: MonadState TLSState m => m ()
switchTxEncryption = modify (\st -> st { stTxEncrypted = True })
switchRxEncryption = modify (\st -> st { stRxEncrypted = True })

setServerRandom :: MonadState TLSState m => ServerRandom -> m ()
setServerRandom ran = updateHandshake "srand" (\hst -> hst { hstServerRandom = Just ran })

setMasterSecret :: MonadState TLSState m => Bytes -> m ()
setMasterSecret premastersecret = do
	st <- get
	hasValidHandshake "master secret"

	updateHandshake "master secret" (\hst ->
		let ms = generateMasterSecret (stVersion st) premastersecret (hstClientRandom hst) (fromJust "server random" $ hstServerRandom hst) in
		hst { hstMasterSecret = Just ms } )
	return ()

setPublicKey :: MonadState TLSState m => PublicKey -> m ()
setPublicKey pk = updateHandshake "publickey" (\hst -> hst { hstRSAPublicKey = Just pk })

setPrivateKey :: MonadState TLSState m => PrivateKey -> m ()
setPrivateKey pk = updateHandshake "privatekey" (\hst -> hst { hstRSAPrivateKey = Just pk })

setKeyBlock :: MonadState TLSState m => m ()
setKeyBlock = do
	st <- get

	let hst = fromJust "handshake" $ stHandshake st

	let cc = stClientContext st
	let cipher = fromJust "cipher" $ stCipher st
	let keyblockSize = fromIntegral $ cipherKeyBlockSize cipher
	let digestSize   = fromIntegral $ cipherDigestSize cipher
	let keySize      = fromIntegral $ cipherKeySize cipher
	let ivSize       = fromIntegral $ cipherIVSize cipher
	let kb = generateKeyBlock (stVersion st) (hstClientRandom hst)
	                          (fromJust "server random" $ hstServerRandom hst)
	                          (fromJust "master secret" $ hstMasterSecret hst) keyblockSize

	let (cMACSecret, sMACSecret, cWriteKey, sWriteKey, cWriteIV, sWriteIV) =
		fromJust "p6" $ partition6 kb (digestSize, digestSize, keySize, keySize, ivSize, ivSize)

	let cstClient = TLSCryptState
		{ cstKey        = cWriteKey
		, cstIV         = cWriteIV
		, cstMacSecret  = cMACSecret }
	let cstServer = TLSCryptState
		{ cstKey        = sWriteKey
		, cstIV         = sWriteIV
		, cstMacSecret  = sMACSecret }
	let msClient = TLSMacState { msSequence = 0 }
	let msServer = TLSMacState { msSequence = 0 }
	put $ st
		{ stTxCryptState = Just $ if cc then cstClient else cstServer
		, stRxCryptState = Just $ if cc then cstServer else cstClient
		, stTxMacState   = Just $ if cc then msClient else msServer
		, stRxMacState   = Just $ if cc then msServer else msClient
		}

setCipher :: MonadState TLSState m => Cipher -> m ()
setCipher cipher = modify (\st -> st { stCipher = Just cipher })

setVersion :: MonadState TLSState m => Version -> m ()
setVersion ver = modify (\st -> st { stVersion = ver })

getCipherKeyExchangeType :: MonadState TLSState m => m (Maybe CipherKeyExchangeType)
getCipherKeyExchangeType = get >>= return . (maybe Nothing (Just . cipherKeyExchange) . stCipher)

isClientContext :: MonadState TLSState m => m Bool
isClientContext = get >>= return . stClientContext

-- create a new empty handshake state
newEmptyHandshake :: Version -> ClientRandom -> TLSHandshakeState
newEmptyHandshake ver crand = TLSHandshakeState
	{ hstClientVersion   = ver
	, hstClientRandom    = crand
	, hstServerRandom    = Nothing
	, hstMasterSecret    = Nothing
	, hstRSAPublicKey    = Nothing
	, hstRSAPrivateKey   = Nothing
	, hstHandshakeDigest = Nothing
	}

startHandshakeClient :: MonadState TLSState m => Version -> ClientRandom -> m ()
startHandshakeClient ver crand = do
	-- FIXME check if handshake is already not null
	chs <- get >>= return . stHandshake
	when (isNothing chs) $
		modify (\st -> st { stHandshake = Just $ newEmptyHandshake ver crand })

hasValidHandshake :: MonadState TLSState m => String -> m ()
hasValidHandshake name = get >>= \st -> assert name [ ("valid handshake", isNothing $ stHandshake st) ]

updateHandshake :: MonadState TLSState m => String -> (TLSHandshakeState -> TLSHandshakeState) -> m ()
updateHandshake n f = do
	hasValidHandshake n
	modify (\st -> st { stHandshake = maybe Nothing (Just . f) (stHandshake st) })

updateHandshakeDigest :: MonadState TLSState m => Bytes -> m ()
updateHandshakeDigest content = updateHandshake "update digest" (\hs ->
	let (c1, c2) = case hstHandshakeDigest hs of
		Nothing                -> (initHash HashTypeSHA1, initHash HashTypeMD5)
		Just (sha1ctx, md5ctx) -> (sha1ctx, md5ctx) in
	let nc1 = updateHash c1 content in
	let nc2 = updateHash c2 content in
	hs { hstHandshakeDigest = Just (nc1, nc2) }
	)

updateHandshakeDigestSplitted :: MonadState TLSState m => HandshakeType -> Bytes -> m ()
updateHandshakeDigestSplitted ty bytes = updateHandshakeDigest $ B.concat [hdr, bytes]
	where
		hdr = runPut $ encodeHandshakeHeader ty (B.length bytes)

getHandshakeDigest :: MonadState TLSState m => Bool -> m Bytes
getHandshakeDigest client = do
	st <- get
	let hst = fromJust "handshake" $ stHandshake st
	let (sha1ctx, md5ctx) = fromJust "handshake digest" $ hstHandshakeDigest hst
	let msecret           = fromJust "master secret" $ hstMasterSecret hst
	return $ (if client then generateClientFinished else generateServerFinished) (stVersion st) msecret md5ctx sha1ctx

endHandshake :: MonadState TLSState m => m ()
endHandshake = modify (\st -> st { stHandshake = Nothing })
