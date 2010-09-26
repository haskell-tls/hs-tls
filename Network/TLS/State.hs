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
	, TLSHandshakeState(..)
	, TLSCryptState(..)
	, TLSMacState(..)
	, MonadTLSState, getTLSState, putTLSState, modifyTLSState
	, newTLSState
	, assert -- FIXME move somewhere else (Internal.hs ?)
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
	, isClientContext
	, startHandshakeClient
	, updateHandshakeDigest
	, getHandshakeDigest
	, endHandshake
	) where

import Data.Word
import Data.Maybe (fromJust, isNothing)
import Network.TLS.Util
import Network.TLS.Struct
import Network.TLS.SRandom
import Network.TLS.Wire
import Network.TLS.Packet
import Network.TLS.Crypto
import Network.TLS.Cipher
import qualified Data.ByteString as B
import Control.Monad

assert :: Monad m => String -> [(String,Bool)] -> m ()
assert fctname list = forM_ list $ \ (name, assumption) -> do
	when assumption $ fail (fctname ++ ": assumption about " ++ name ++ " failed")

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

data TLSState = TLSState
	{ stClientContext :: Bool
	, stVersion       :: !Version
	, stHandshake     :: !(Maybe TLSHandshakeState)
	, stTxEncrypted   :: Bool
	, stRxEncrypted   :: Bool
	, stTxCryptState  :: !(Maybe TLSCryptState)
	, stRxCryptState  :: !(Maybe TLSCryptState)
	, stTxMacState    :: !(Maybe TLSMacState)
	, stRxMacState    :: !(Maybe TLSMacState)
	, stCipher        :: Maybe Cipher
	, stRandomGen     :: SRandomGen
	} deriving (Show)

class (Monad m) => MonadTLSState m where
	getTLSState :: m TLSState
	putTLSState :: TLSState -> m ()

newTLSState :: SRandomGen -> TLSState
newTLSState rng = TLSState
	{ stClientContext = False
	, stVersion       = TLS10
	, stHandshake     = Nothing
	, stTxEncrypted   = False
	, stRxEncrypted   = False
	, stTxCryptState  = Nothing
	, stRxCryptState  = Nothing
	, stTxMacState    = Nothing
	, stRxMacState    = Nothing
	, stCipher        = Nothing
	, stRandomGen     = rng
	}

modifyTLSState :: (MonadTLSState m) => (TLSState -> TLSState) -> m ()
modifyTLSState f = getTLSState >>= \st -> putTLSState (f st)

makeDigest :: (MonadTLSState m) => Bool -> Header -> Bytes -> m Bytes
makeDigest w hdr content = do
	st <- getTLSState
	assert "make digest"
		[ ("cipher", isNothing $ stCipher st)
		, ("crypt state", isNothing $ if w then stTxCryptState st else stRxCryptState st)
		, ("mac state", isNothing $ if w then stTxMacState st else stRxMacState st) ]
	let cst = fromJust $ if w then stTxCryptState st else stRxCryptState st
	let ms = fromJust $ if w then stTxMacState st else stRxMacState st
	let cipher = fromJust $ stCipher st

	let hmac_msg = B.concat [ encodeWord64 $ msSequence ms, encodeHeader hdr, content ]
	let digest = (cipherHMAC cipher) (cstMacSecret cst) hmac_msg

	let newms = ms { msSequence = (msSequence ms) + 1 }

	modifyTLSState (\_ -> if w then st { stTxMacState = Just newms } else st { stRxMacState = Just newms })
	return digest

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

switchTxEncryption :: MonadTLSState m => m ()
switchTxEncryption = getTLSState >>= putTLSState . (\st -> st { stTxEncrypted = True })

switchRxEncryption :: MonadTLSState m => m ()
switchRxEncryption = getTLSState >>= putTLSState . (\st -> st { stRxEncrypted = True })

setServerRandom :: MonadTLSState m => ServerRandom -> m ()
setServerRandom ran = updateHandshake "srand" (\hst -> hst { hstServerRandom = Just ran })

setMasterSecret :: MonadTLSState m => Bytes -> m ()
setMasterSecret premastersecret = do
	st <- getTLSState
	hasValidHandshake "master secret"
	assert "set master secret"
		[ ("server random", (isNothing $ hstServerRandom $ fromJust $ stHandshake st)) ]

	updateHandshake "master secret" (\hst ->
		let ms = generateMasterSecret (stVersion st) premastersecret (hstClientRandom hst) (fromJust $ hstServerRandom hst) in
		hst { hstMasterSecret = Just ms } )
	return ()

setPublicKey :: MonadTLSState m => PublicKey -> m ()
setPublicKey pk = updateHandshake "publickey" (\hst -> hst { hstRSAPublicKey = Just pk })

setPrivateKey :: MonadTLSState m => PrivateKey -> m ()
setPrivateKey pk = updateHandshake "privatekey" (\hst -> hst { hstRSAPrivateKey = Just pk })

setKeyBlock :: MonadTLSState m => m ()
setKeyBlock = do
	st <- getTLSState

	let hst = fromJust $ stHandshake st
	assert "set key block"
		[ ("cipher", (isNothing $ stCipher st))
		, ("server random", (isNothing $ hstServerRandom hst))
		, ("master secret", (isNothing $ hstMasterSecret hst))
		]

	let cc = stClientContext st
	let cipher = fromJust $ stCipher st
	let keyblockSize = fromIntegral $ cipherKeyBlockSize cipher
	let digestSize = fromIntegral $ cipherDigestSize cipher
	let keySize = fromIntegral $ cipherKeySize cipher
	let ivSize = fromIntegral $ cipherIVSize cipher
	let kb = generateKeyBlock (hstClientRandom hst)
	                          (fromJust $ hstServerRandom hst)
	                          (fromJust $ hstMasterSecret hst) keyblockSize

	let (cMACSecret, sMACSecret, cWriteKey, sWriteKey, cWriteIV, sWriteIV) =
		fromJust $ partition6 kb (digestSize, digestSize, keySize, keySize, ivSize, ivSize)

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
	putTLSState $ st
		{ stTxCryptState = Just $ if cc then cstClient else cstServer
		, stRxCryptState = Just $ if cc then cstServer else cstClient
		, stTxMacState   = Just $ if cc then msClient else msServer
		, stRxMacState   = Just $ if cc then msServer else msClient
		}

setCipher :: MonadTLSState m => Cipher -> m ()
setCipher cipher = getTLSState >>= putTLSState . (\st -> st { stCipher = Just cipher })

setVersion :: MonadTLSState m => Version -> m ()
setVersion ver = getTLSState >>= putTLSState . (\st -> st { stVersion = ver })

isClientContext :: MonadTLSState m => m Bool
isClientContext = getTLSState >>= return . stClientContext

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

startHandshakeClient :: MonadTLSState m => Version -> ClientRandom -> m ()
startHandshakeClient ver crand = do
	-- FIXME check if handshake is already not null
	chs <- getTLSState >>= return . stHandshake
	when (isNothing chs) $
		modifyTLSState (\st -> st { stHandshake = Just $ newEmptyHandshake ver crand })

hasValidHandshake :: MonadTLSState m => String -> m ()
hasValidHandshake name = getTLSState >>= \st -> assert name [ ("valid handshake", isNothing $ stHandshake st) ]

updateHandshake :: MonadTLSState m => String -> (TLSHandshakeState -> TLSHandshakeState) -> m ()
updateHandshake n f = do
	hasValidHandshake n
	modifyTLSState (\st -> st { stHandshake = maybe Nothing (Just . f) (stHandshake st) })

updateHandshakeDigest :: MonadTLSState m => Bytes -> m ()
updateHandshakeDigest content = updateHandshake "update digest" (\hs ->
	let (c1, c2) = case hstHandshakeDigest hs of
		Nothing                -> (initHash HashTypeSHA1, initHash HashTypeMD5)
		Just (sha1ctx, md5ctx) -> (sha1ctx, md5ctx) in
	let nc1 = updateHash c1 content in
	let nc2 = updateHash c2 content in
	hs { hstHandshakeDigest = Just (nc1, nc2) }
	)

getHandshakeDigest :: MonadTLSState m => Bool -> m Bytes
getHandshakeDigest client = do
	st <- getTLSState
	let hst = fromJust $ stHandshake st
	let (sha1ctx, md5ctx) = fromJust $ hstHandshakeDigest hst
	let msecret = fromJust $ hstMasterSecret hst
	return $ (if client then generateClientFinished else generateServerFinished) (stVersion st) msecret md5ctx sha1ctx

endHandshake :: MonadTLSState m => m ()
endHandshake = modifyTLSState (\st -> st { stHandshake = Nothing })
