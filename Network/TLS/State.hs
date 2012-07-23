{-# LANGUAGE GeneralizedNewtypeDeriving, FlexibleContexts, MultiParamTypeClasses, ExistentialQuantification, RankNTypes, CPP #-}
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
        , newTLSState
        , genTLSRandom
        , withTLSRNG
        , withCompression
        , assert -- FIXME move somewhere else (Internal.hs ?)
        , updateVerifiedData
        , finishHandshakeTypeMaterial
        , finishHandshakeMaterial
        , makeDigest
        , setMasterSecret
        , setMasterSecretFromPre
        , setPublicKey
        , setPrivateKey
        , setKeyBlock
        , setVersion
        , setCipher
        , setServerRandom
        , setSecureRenegotiation
        , getSecureRenegotiation
        , setExtensionNPN
        , getExtensionNPN
        , setNegotiatedProtocol
        , getNegotiatedProtocol
        , setServerNextProtocolSuggest
        , getServerNextProtocolSuggest
        , getVerifiedData
        , setSession
        , getSession
        , getSessionData
        , isSessionResuming
        , needEmptyPacket
        , switchTxEncryption
        , switchRxEncryption
        , getCipherKeyExchangeType
        , isClientContext
        , startHandshakeClient
        , updateHandshakeDigest
        , getHandshakeDigest
        , endHandshake
        ) where

import Data.Word
import Data.Maybe (isNothing)
import Network.TLS.Util
import Network.TLS.Struct
import Network.TLS.Wire
import Network.TLS.Packet
import Network.TLS.Crypto
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.MAC
import qualified Data.ByteString as B
import Control.Applicative ((<$>))
import Control.Monad
import Control.Monad.State
import Control.Monad.Error
import Crypto.Random

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
        , hstHandshakeDigest :: !HashCtx
        } deriving (Show)

data StateRNG = forall g . CryptoRandomGen g => StateRNG g

instance Show StateRNG where
        show _ = "rng[..]"

data TLSState = TLSState
        { stClientContext       :: Bool
        , stVersion             :: !Version
        , stHandshake           :: !(Maybe TLSHandshakeState)
        , stSession             :: Session
        , stSessionResuming     :: Bool
        , stTxEncrypted         :: Bool
        , stRxEncrypted         :: Bool
        , stTxCryptState        :: !(Maybe TLSCryptState)
        , stRxCryptState        :: !(Maybe TLSCryptState)
        , stTxMacState          :: !(Maybe TLSMacState)
        , stRxMacState          :: !(Maybe TLSMacState)
        , stCipher              :: Maybe Cipher
        , stCompression         :: Compression
        , stRandomGen           :: StateRNG
        , stSecureRenegotiation :: Bool  -- RFC 5746
        , stClientVerifiedData  :: Bytes -- RFC 5746
        , stServerVerifiedData  :: Bytes -- RFC 5746
        , stExtensionNPN        :: Bool  -- NPN draft extension
        , stNegotiatedProtocol  :: Maybe B.ByteString -- NPN protocol
        , stServerNextProtocolSuggest :: Maybe [B.ByteString]
        } deriving (Show)

newtype TLSSt a = TLSSt { runTLSSt :: ErrorT TLSError (State TLSState) a }
        deriving (Monad, MonadError TLSError)

instance Functor TLSSt where
        fmap f = TLSSt . fmap f . runTLSSt

instance MonadState TLSState TLSSt where
        put x = TLSSt (lift $ put x)
        get   = TLSSt (lift get)
#if MIN_VERSION_mtl(2,1,0)
        state f = TLSSt (lift $ state f)
#endif

runTLSState :: TLSSt a -> TLSState -> (Either TLSError a, TLSState)
runTLSState f st = runState (runErrorT (runTLSSt f)) st

newTLSState :: CryptoRandomGen g => g -> TLSState
newTLSState rng = TLSState
        { stClientContext       = False
        , stVersion             = TLS10
        , stHandshake           = Nothing
        , stSession             = Session Nothing
        , stSessionResuming     = False
        , stTxEncrypted         = False
        , stRxEncrypted         = False
        , stTxCryptState        = Nothing
        , stRxCryptState        = Nothing
        , stTxMacState          = Nothing
        , stRxMacState          = Nothing
        , stCipher              = Nothing
        , stCompression         = nullCompression
        , stRandomGen           = StateRNG rng
        , stSecureRenegotiation = False
        , stClientVerifiedData  = B.empty
        , stServerVerifiedData  = B.empty
        , stExtensionNPN        = False
        , stNegotiatedProtocol  = Nothing
        , stServerNextProtocolSuggest = Nothing
        }

withTLSRNG :: StateRNG -> (forall g . CryptoRandomGen g => g -> Either e (a,g)) -> Either e (a, StateRNG)
withTLSRNG (StateRNG rng) f = case f rng of
        Left err        -> Left err
        Right (a, rng') -> Right (a, StateRNG rng')

withCompression :: (Compression -> (Compression, a)) -> TLSSt a
withCompression f = do
        compression <- stCompression <$> get
        let (nc, a) = f compression
        modify (\st -> st { stCompression = nc })
        return a

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
        let hashf = hashF $ cipherHash cipher

        let (macF, msg) =
                if ver < TLS10
                        then (macSSL hashf, B.concat [ encodeWord64 $ msSequence ms, encodeHeaderNoVer hdr, content ])
                        else (hmac hashf 64, B.concat [ encodeWord64 $ msSequence ms, encodeHeader hdr, content ])
        let digest = macF (cstMacSecret cst) msg

        let newms = ms { msSequence = (msSequence ms) + 1 }

        modify (\_ -> if w then st { stTxMacState = Just newms } else st { stRxMacState = Just newms })
        return digest

updateVerifiedData :: MonadState TLSState m => Bool -> Bytes -> m ()
updateVerifiedData sending bs = do
        cc <- isClientContext
        if cc /= sending
                then modify (\st -> st { stServerVerifiedData = bs })
                else modify (\st -> st { stClientVerifiedData = bs })

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
finishHandshakeTypeMaterial HandshakeType_NPN             = True

finishHandshakeMaterial :: Handshake -> Bool
finishHandshakeMaterial = finishHandshakeTypeMaterial . typeOfHandshake

switchTxEncryption, switchRxEncryption :: MonadState TLSState m => m ()
switchTxEncryption = modify (\st -> st { stTxEncrypted = True })
switchRxEncryption = modify (\st -> st { stRxEncrypted = True })

setServerRandom :: MonadState TLSState m => ServerRandom -> m ()
setServerRandom ran = updateHandshake "srand" (\hst -> hst { hstServerRandom = Just ran })

setMasterSecret :: MonadState TLSState m => Bytes -> m ()
setMasterSecret masterSecret = do
        hasValidHandshake "master secret"

        updateHandshake "master secret" (\hst -> hst { hstMasterSecret = Just masterSecret } )
        setKeyBlock
        return ()

setMasterSecretFromPre :: MonadState TLSState m => Bytes -> m ()
setMasterSecretFromPre premasterSecret = do
        hasValidHandshake "generate master secret"
        st <- get
        setMasterSecret $ genSecret st
        where
                genSecret st =
                        let hst = fromJust "handshake" $ stHandshake st in
                        generateMasterSecret (stVersion st)
                                             premasterSecret
                                             (hstClientRandom hst)
                                             (fromJust "server random" $ hstServerRandom hst)

setPublicKey :: MonadState TLSState m => PublicKey -> m ()
setPublicKey pk = updateHandshake "publickey" (\hst -> hst { hstRSAPublicKey = Just pk })

setPrivateKey :: MonadState TLSState m => PrivateKey -> m ()
setPrivateKey pk = updateHandshake "privatekey" (\hst -> hst { hstRSAPrivateKey = Just pk })

getSessionData :: MonadState TLSState m => m (Maybe SessionData)
getSessionData = do
        st <- get
        return (stHandshake st >>= hstMasterSecret >>= wrapSessionData st)
        where wrapSessionData st masterSecret = do
                return $ SessionData
                        { sessionVersion = stVersion st
                        , sessionCipher  = cipherID $ fromJust "cipher" $ stCipher st
                        , sessionSecret  = masterSecret
                        }

setSession :: MonadState TLSState m => Session -> Bool -> m ()
setSession session resuming = modify (\st -> st { stSession = session, stSessionResuming = resuming })

getSession :: MonadState TLSState m => m Session
getSession = gets stSession

isSessionResuming :: MonadState TLSState m => m Bool
isSessionResuming = gets stSessionResuming

needEmptyPacket :: MonadState TLSState m => m Bool
needEmptyPacket = gets f
    where f st = (stVersion st <= TLS10)
              && (maybe False (\c -> bulkBlockSize (cipherBulk c) > 0) (stCipher st))

setKeyBlock :: MonadState TLSState m => m ()
setKeyBlock = do
        st <- get

        let hst = fromJust "handshake" $ stHandshake st

        let cc = stClientContext st
        let cipher = fromJust "cipher" $ stCipher st
        let keyblockSize = cipherKeyBlockSize cipher

        let bulk = cipherBulk cipher
        let digestSize   = hashSize $ cipherHash cipher
        let keySize      = bulkKeySize bulk
        let ivSize       = bulkIVSize bulk
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

setSecureRenegotiation :: MonadState TLSState m => Bool -> m ()
setSecureRenegotiation b = modify (\st -> st { stSecureRenegotiation = b })

getSecureRenegotiation :: MonadState TLSState m => m Bool
getSecureRenegotiation = get >>= return . stSecureRenegotiation

setExtensionNPN :: MonadState TLSState m => Bool -> m ()
setExtensionNPN b = modify (\st -> st { stExtensionNPN = b })

getExtensionNPN :: MonadState TLSState m => m Bool
getExtensionNPN = get >>= return . stExtensionNPN

setNegotiatedProtocol :: MonadState TLSState m => B.ByteString -> m ()
setNegotiatedProtocol s = modify (\st -> st { stNegotiatedProtocol = Just s })

getNegotiatedProtocol :: MonadState TLSState m => m (Maybe B.ByteString)
getNegotiatedProtocol = get >>= return . stNegotiatedProtocol

setServerNextProtocolSuggest :: MonadState TLSState m => [B.ByteString] -> m ()
setServerNextProtocolSuggest ps = modify (\st -> st { stServerNextProtocolSuggest = Just ps})

getServerNextProtocolSuggest :: MonadState TLSState m => m (Maybe [B.ByteString])
getServerNextProtocolSuggest = get >>= return . stServerNextProtocolSuggest

getCipherKeyExchangeType :: MonadState TLSState m => m (Maybe CipherKeyExchangeType)
getCipherKeyExchangeType = get >>= return . (maybe Nothing (Just . cipherKeyExchange) . stCipher)

getVerifiedData :: MonadState TLSState m => Bool -> m Bytes
getVerifiedData client = get >>= return . (if client then stClientVerifiedData else stServerVerifiedData)

isClientContext :: MonadState TLSState m => m Bool
isClientContext = get >>= return . stClientContext

-- create a new empty handshake state
newEmptyHandshake :: Version -> ClientRandom -> HashCtx -> TLSHandshakeState
newEmptyHandshake ver crand digestInit = TLSHandshakeState
        { hstClientVersion   = ver
        , hstClientRandom    = crand
        , hstServerRandom    = Nothing
        , hstMasterSecret    = Nothing
        , hstRSAPublicKey    = Nothing
        , hstRSAPrivateKey   = Nothing
        , hstHandshakeDigest = digestInit
        }

startHandshakeClient :: MonadState TLSState m => Version -> ClientRandom -> m ()
startHandshakeClient ver crand = do
        -- FIXME check if handshake is already not null
        let initCtx = if ver < TLS12 then hashMD5SHA1 else hashSHA256
        chs <- get >>= return . stHandshake
        when (isNothing chs) $
                modify (\st -> st { stHandshake = Just $ newEmptyHandshake ver crand initCtx })

hasValidHandshake :: MonadState TLSState m => String -> m ()
hasValidHandshake name = get >>= \st -> assert name [ ("valid handshake", isNothing $ stHandshake st) ]

updateHandshake :: MonadState TLSState m => String -> (TLSHandshakeState -> TLSHandshakeState) -> m ()
updateHandshake n f = do
        hasValidHandshake n
        modify (\st -> st { stHandshake = f <$> stHandshake st })

updateHandshakeDigest :: MonadState TLSState m => Bytes -> m ()
updateHandshakeDigest content = updateHandshake "update digest" $ \hs ->
        hs { hstHandshakeDigest = hashUpdate (hstHandshakeDigest hs) content }

getHandshakeDigest :: MonadState TLSState m => Bool -> m Bytes
getHandshakeDigest client = do
        st <- get
        let hst = fromJust "handshake" $ stHandshake st
        let hashctx = hstHandshakeDigest hst
        let msecret = fromJust "master secret" $ hstMasterSecret hst
        return $ (if client then generateClientFinished else generateServerFinished) (stVersion st) msecret hashctx

endHandshake :: MonadState TLSState m => m ()
endHandshake = modify (\st -> st { stHandshake = Nothing })
