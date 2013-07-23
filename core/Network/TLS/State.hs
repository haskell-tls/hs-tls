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
    , RecordState(..)
    , getRecordState
    , runTLSState
    , runRecordStateSt
    , HandshakeState(..)
    , withHandshakeM
    , newTLSState
    , withTLSRNG
    , genRandom
    , assert -- FIXME move somewhere else (Internal.hs ?)
    , updateVerifiedData
    , finishHandshakeTypeMaterial
    , finishHandshakeMaterial
    , certVerifyHandshakeTypeMaterial
    , certVerifyHandshakeMaterial
    , setVersion
    , getVersion
    , setSecureRenegotiation
    , getSecureRenegotiation
    , setExtensionNPN
    , getExtensionNPN
    , setNegotiatedProtocol
    , getNegotiatedProtocol
    , setServerNextProtocolSuggest
    , getServerNextProtocolSuggest
    , getClientCertificateChain
    , setClientCertificateChain
    , getVerifiedData
    , setSession
    , getSession
    , getSessionData
    , isSessionResuming
    , needEmptyPacket
    , switchTxEncryption
    , switchRxEncryption
    , isClientContext
    , startHandshakeClient
    , getHandshakeDigest
    , endHandshake
    ) where

import Data.Maybe (isNothing)
import Network.TLS.Util
import Network.TLS.Struct
import Network.TLS.Packet
import Network.TLS.Crypto
import Network.TLS.Cipher
import Network.TLS.Record.State
import Network.TLS.Handshake.State
import Network.TLS.RNG
import Network.TLS.Types (Role(..))
import qualified Data.ByteString as B
import Control.Monad
import Control.Monad.State
import Control.Monad.Error
import Crypto.Random.API
import Data.X509 (CertificateChain)

assert :: Monad m => String -> [(String,Bool)] -> m ()
assert fctname list = forM_ list $ \ (name, assumption) -> do
    when assumption $ fail (fctname ++ ": assumption about " ++ name ++ " failed")

data TLSState = TLSState
    { stHandshake           :: !(Maybe HandshakeState)
    , stSession             :: Session
    , stSessionResuming     :: Bool
    , stRecordState         :: RecordState
    , stSecureRenegotiation :: Bool  -- RFC 5746
    , stClientVerifiedData  :: Bytes -- RFC 5746
    , stServerVerifiedData  :: Bytes -- RFC 5746
    , stExtensionNPN        :: Bool  -- NPN draft extension
    , stNegotiatedProtocol  :: Maybe B.ByteString -- NPN protocol
    , stServerNextProtocolSuggest :: Maybe [B.ByteString]
    , stClientCertificateChain :: Maybe CertificateChain
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

getRecordState :: MonadState TLSState m => (RecordState -> a) -> m a
getRecordState f = gets (f . stRecordState)

runRecordState :: RecordM a -> TLSState -> (Either TLSError a, TLSState)
runRecordState f st =
    let (r, nrst) = runState (runErrorT (runRecordM f)) (stRecordState st)
     in case r of
            Left _  -> (r, st)
            Right _ -> (r, st { stRecordState = nrst })

runRecordStateSt :: RecordM a -> TLSSt a
runRecordStateSt f = do
    st <- get
    case runRecordState f st of
        (Left e, _)      -> throwError e
        (Right a, newSt) -> put newSt >> return a

newTLSState :: CPRG g => g -> Role -> TLSState
newTLSState rng clientContext = TLSState
    { stHandshake           = Nothing
    , stSession             = Session Nothing
    , stSessionResuming     = False
    , stRecordState         = newRecordState rng clientContext
    , stSecureRenegotiation = False
    , stClientVerifiedData  = B.empty
    , stServerVerifiedData  = B.empty
    , stExtensionNPN        = False
    , stNegotiatedProtocol  = Nothing
    , stServerNextProtocolSuggest = Nothing
    , stClientCertificateChain = Nothing
    }

updateVerifiedData :: MonadState TLSState m => Role -> Bytes -> m ()
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
finishHandshakeTypeMaterial HandshakeType_CertVerify      = True
finishHandshakeTypeMaterial HandshakeType_Finished        = True
finishHandshakeTypeMaterial HandshakeType_NPN             = True

finishHandshakeMaterial :: Handshake -> Bool
finishHandshakeMaterial = finishHandshakeTypeMaterial . typeOfHandshake

certVerifyHandshakeTypeMaterial :: HandshakeType -> Bool
certVerifyHandshakeTypeMaterial HandshakeType_ClientHello     = True
certVerifyHandshakeTypeMaterial HandshakeType_ServerHello     = True
certVerifyHandshakeTypeMaterial HandshakeType_Certificate     = True
certVerifyHandshakeTypeMaterial HandshakeType_HelloRequest    = False
certVerifyHandshakeTypeMaterial HandshakeType_ServerHelloDone = True
certVerifyHandshakeTypeMaterial HandshakeType_ClientKeyXchg   = True
certVerifyHandshakeTypeMaterial HandshakeType_ServerKeyXchg   = True
certVerifyHandshakeTypeMaterial HandshakeType_CertRequest     = True
certVerifyHandshakeTypeMaterial HandshakeType_CertVerify      = False
certVerifyHandshakeTypeMaterial HandshakeType_Finished        = False
certVerifyHandshakeTypeMaterial HandshakeType_NPN             = False

certVerifyHandshakeMaterial :: Handshake -> Bool
certVerifyHandshakeMaterial = certVerifyHandshakeTypeMaterial . typeOfHandshake

switchTxEncryption, switchRxEncryption :: TLSSt ()
switchTxEncryption =
        withHandshakeM (gets hstPendingTxState)
    >>= \newTxState -> runRecordStateSt (modify $ \st -> st { stTxState = fromJust "pending-tx" newTxState })
switchRxEncryption =
        withHandshakeM (gets hstPendingRxState)
    >>= \newRxState -> runRecordStateSt (modify $ \st -> st { stRxState = fromJust "pending-rx" newRxState })

getSessionData :: MonadState TLSState m => m (Maybe SessionData)
getSessionData = get >>= \st -> return (stHandshake st >>= hstMasterSecret >>= wrapSessionData st)
  where wrapSessionData st masterSecret = do
            return $ SessionData
                    { sessionVersion = stVersion $ stRecordState st
                    , sessionCipher  = cipherID $ fromJust "cipher" $ stCipher $ stTxState $ stRecordState st
                    , sessionSecret  = masterSecret
                    }

setSession :: MonadState TLSState m => Session -> Bool -> m ()
setSession session resuming = modify (\st -> st { stSession = session, stSessionResuming = resuming })

getSession :: MonadState TLSState m => m Session
getSession = gets stSession

isSessionResuming :: MonadState TLSState m => m Bool
isSessionResuming = gets stSessionResuming

needEmptyPacket :: MonadState RecordState m => m Bool
needEmptyPacket = gets f
  where f st = (stVersion st <= TLS10)
            && stClientContext st == ClientRole
            && (maybe False (\c -> bulkBlockSize (cipherBulk c) > 0) (stCipher $ stTxState st))

setVersion :: MonadState TLSState m => Version -> m ()
setVersion ver = modify (\st -> st { stRecordState = (stRecordState st) { stVersion = ver } })

getVersion :: MonadState TLSState m => m Version
getVersion = gets (stVersion . stRecordState)

setSecureRenegotiation :: MonadState TLSState m => Bool -> m ()
setSecureRenegotiation b = modify (\st -> st { stSecureRenegotiation = b })

getSecureRenegotiation :: MonadState TLSState m => m Bool
getSecureRenegotiation = gets stSecureRenegotiation

setExtensionNPN :: MonadState TLSState m => Bool -> m ()
setExtensionNPN b = modify (\st -> st { stExtensionNPN = b })

getExtensionNPN :: MonadState TLSState m => m Bool
getExtensionNPN = gets stExtensionNPN

setNegotiatedProtocol :: MonadState TLSState m => B.ByteString -> m ()
setNegotiatedProtocol s = modify (\st -> st { stNegotiatedProtocol = Just s })

getNegotiatedProtocol :: MonadState TLSState m => m (Maybe B.ByteString)
getNegotiatedProtocol = gets stNegotiatedProtocol

setServerNextProtocolSuggest :: MonadState TLSState m => [B.ByteString] -> m ()
setServerNextProtocolSuggest ps = modify (\st -> st { stServerNextProtocolSuggest = Just ps})

getServerNextProtocolSuggest :: MonadState TLSState m => m (Maybe [B.ByteString])
getServerNextProtocolSuggest = get >>= return . stServerNextProtocolSuggest

setClientCertificateChain :: MonadState TLSState m => CertificateChain -> m ()
setClientCertificateChain s = modify (\st -> st { stClientCertificateChain = Just s })

getClientCertificateChain :: MonadState TLSState m => m (Maybe CertificateChain)
getClientCertificateChain = gets stClientCertificateChain

getVerifiedData :: MonadState TLSState m => Bool -> m Bytes
getVerifiedData client = gets (if client then stClientVerifiedData else stServerVerifiedData)

isClientContext :: MonadState TLSState m => m Role
isClientContext = getRecordState stClientContext

startHandshakeClient :: MonadState TLSState m => Version -> ClientRandom -> m ()
startHandshakeClient ver crand = do
    -- FIXME check if handshake is already not null
    let initCtx = if ver < TLS12 then hashMD5SHA1 else hashSHA256
    chs <- get >>= return . stHandshake
    when (isNothing chs) $
        modify (\st -> st { stHandshake = Just $ newEmptyHandshake ver crand initCtx })

withHandshakeM :: MonadState TLSState m => HandshakeM a -> m a
withHandshakeM f =
    get >>= \st -> case stHandshake st of
                    Nothing  -> fail "handshake missing"
                    Just hst -> do let (a, nhst) = runHandshake hst f
                                   put (st { stHandshake = Just nhst })
                                   return a

getHandshakeDigest :: MonadState TLSState m => Bool -> m Bytes
getHandshakeDigest roleClient = do
    st <- get
    let hst = fromJust "handshake" $ stHandshake st
    let hashctx = hstHandshakeDigest hst
    let msecret = fromJust "master secret" $ hstMasterSecret hst
    return $ (if roleClient then generateClientFinished else generateServerFinished) (stVersion $ stRecordState st) msecret hashctx

endHandshake :: MonadState TLSState m => m ()
endHandshake = modify (\st -> st { stHandshake = Nothing })

genRandom :: Int -> TLSSt Bytes
genRandom n = runRecordStateSt (genTLSRandom n)
