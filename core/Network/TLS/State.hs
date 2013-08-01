{-# LANGUAGE CPP #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts #-}
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
    , HandshakeState(..)
    , withHandshakeM
    , newTLSState
    , withTLSRNG
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
    , isSessionResuming
    , isClientContext
    , getHandshakeDigest
    , endHandshake
    -- * random
    , genRandom
    , withRNG
    ) where

import Control.Applicative
import Network.TLS.Struct
import Network.TLS.RNG
import Network.TLS.Handshake.State
import Network.TLS.Types (Role(..))
import qualified Data.ByteString as B
import Control.Monad.State
import Control.Monad.Error
import Crypto.Random.API
import Data.X509 (CertificateChain)

data TLSState = TLSState
    { stHandshake           :: !(Maybe HandshakeState)
    , stSession             :: Session
    , stSessionResuming     :: Bool
    , stSecureRenegotiation :: Bool  -- RFC 5746
    , stClientVerifiedData  :: Bytes -- RFC 5746
    , stServerVerifiedData  :: Bytes -- RFC 5746
    , stExtensionNPN        :: Bool  -- NPN draft extension
    , stNegotiatedProtocol  :: Maybe B.ByteString -- NPN protocol
    , stServerNextProtocolSuggest :: Maybe [B.ByteString]
    , stClientCertificateChain :: Maybe CertificateChain
    , stRandomGen                 :: StateRNG
    , stVersion             :: Version
    , stClientContext       :: Role
    } deriving (Show)

newtype TLSSt a = TLSSt { runTLSSt :: ErrorT TLSError (State TLSState) a }
    deriving (Monad, MonadError TLSError, Functor, Applicative)

instance MonadState TLSState TLSSt where
    put x = TLSSt (lift $ put x)
    get   = TLSSt (lift get)
#if MIN_VERSION_mtl(2,1,0)
    state f = TLSSt (lift $ state f)
#endif

runTLSState :: TLSSt a -> TLSState -> (Either TLSError a, TLSState)
runTLSState f st = runState (runErrorT (runTLSSt f)) st

newTLSState :: CPRG g => g -> Role -> TLSState
newTLSState rng clientContext = TLSState
    { stHandshake           = Nothing
    , stSession             = Session Nothing
    , stSessionResuming     = False
    , stSecureRenegotiation = False
    , stClientVerifiedData  = B.empty
    , stServerVerifiedData  = B.empty
    , stExtensionNPN        = False
    , stNegotiatedProtocol  = Nothing
    , stServerNextProtocolSuggest = Nothing
    , stClientCertificateChain = Nothing
    , stRandomGen           = StateRNG rng
    , stVersion             = TLS10
    , stClientContext       = clientContext
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

setSession :: MonadState TLSState m => Session -> Bool -> m ()
setSession session resuming = modify (\st -> st { stSession = session, stSessionResuming = resuming })

getSession :: MonadState TLSState m => m Session
getSession = gets stSession

isSessionResuming :: MonadState TLSState m => m Bool
isSessionResuming = gets stSessionResuming

setVersion :: MonadState TLSState m => Version -> m ()
setVersion ver = modify (\st -> st { stVersion = ver })

getVersion :: MonadState TLSState m => m Version
getVersion = gets stVersion

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

getVerifiedData :: MonadState TLSState m => Role -> m Bytes
getVerifiedData client = gets (if client == ClientRole then stClientVerifiedData else stServerVerifiedData)

isClientContext :: MonadState TLSState m => m Role
isClientContext = gets stClientContext

withHandshakeM :: MonadState TLSState m => HandshakeM a -> m a
withHandshakeM f =
    get >>= \st -> case stHandshake st of
                    Nothing  -> fail "handshake missing"
                    Just hst -> do let (a, nhst) = runHandshake hst f
                                   put (st { stHandshake = Just nhst })
                                   return a

endHandshake :: MonadState TLSState m => m ()
endHandshake = modify (\st -> st { stHandshake = Nothing })

genRandom :: Int -> TLSSt Bytes
genRandom n = do
    st <- get
    case withTLSRNG (stRandomGen st) (genRandomBytes n) of
            (bytes, rng') -> put (st { stRandomGen = rng' }) >> return bytes

withRNG :: (forall g . CPRG g => g -> (a, g)) -> TLSSt a
withRNG f = do
    st <- get
    let (a,rng') = withTLSRNG (stRandomGen st) f
    put (st { stRandomGen = rng' })
    return a
