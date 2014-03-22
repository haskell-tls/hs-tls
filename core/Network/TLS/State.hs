{-# LANGUAGE CPP #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
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
    , newTLSState
    , withTLSRNG
    , updateVerifiedData
    , finishHandshakeTypeMaterial
    , finishHandshakeMaterial
    , certVerifyHandshakeTypeMaterial
    , certVerifyHandshakeMaterial
    , setVersion
    , setVersionIfUnset
    , getVersion
    , getVersionWithDefault
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
    -- * random
    , genRandom
    , withRNG
    ) where

import Control.Applicative
import Network.TLS.Struct
import Network.TLS.RNG
import Network.TLS.Types (Role(..))
import Network.TLS.Wire (GetContinuation)
import qualified Data.ByteString as B
import Control.Monad.State
import Control.Monad.Error
import Crypto.Random
import Data.X509 (CertificateChain)

data TLSState = TLSState
    { stSession             :: Session
    , stSessionResuming     :: Bool
    , stSecureRenegotiation :: Bool  -- RFC 5746
    , stClientVerifiedData  :: Bytes -- RFC 5746
    , stServerVerifiedData  :: Bytes -- RFC 5746
    , stExtensionNPN        :: Bool  -- NPN draft extension
    , stHandshakeRecordCont :: Maybe (GetContinuation (HandshakeType, Bytes))
    , stNegotiatedProtocol  :: Maybe B.ByteString -- NPN protocol
    , stServerNextProtocolSuggest :: Maybe [B.ByteString]
    , stClientCertificateChain :: Maybe CertificateChain
    , stRandomGen           :: StateRNG
    , stVersion             :: Maybe Version
    , stClientContext       :: Role
    }

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
    { stSession             = Session Nothing
    , stSessionResuming     = False
    , stSecureRenegotiation = False
    , stClientVerifiedData  = B.empty
    , stServerVerifiedData  = B.empty
    , stExtensionNPN        = False
    , stHandshakeRecordCont = Nothing
    , stNegotiatedProtocol  = Nothing
    , stServerNextProtocolSuggest = Nothing
    , stClientCertificateChain = Nothing
    , stRandomGen           = StateRNG rng
    , stVersion             = Nothing
    , stClientContext       = clientContext
    }

updateVerifiedData :: Role -> Bytes -> TLSSt ()
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

setSession :: Session -> Bool -> TLSSt ()
setSession session resuming = modify (\st -> st { stSession = session, stSessionResuming = resuming })

getSession :: TLSSt Session
getSession = gets stSession

isSessionResuming :: TLSSt Bool
isSessionResuming = gets stSessionResuming

setVersion :: Version -> TLSSt ()
setVersion ver = modify (\st -> st { stVersion = Just ver })

setVersionIfUnset :: Version -> TLSSt ()
setVersionIfUnset ver = modify maybeSet
  where maybeSet st = case stVersion st of
                           Nothing -> st { stVersion = Just ver }
                           Just _  -> st

getVersion :: TLSSt Version
getVersion = maybe (error $ "internal error: version hasn't been set yet") id <$> gets stVersion

getVersionWithDefault :: Version -> TLSSt Version
getVersionWithDefault defaultVer = maybe defaultVer id <$> gets stVersion

setSecureRenegotiation :: Bool -> TLSSt ()
setSecureRenegotiation b = modify (\st -> st { stSecureRenegotiation = b })

getSecureRenegotiation :: TLSSt Bool
getSecureRenegotiation = gets stSecureRenegotiation

setExtensionNPN :: Bool -> TLSSt ()
setExtensionNPN b = modify (\st -> st { stExtensionNPN = b })

getExtensionNPN :: TLSSt Bool
getExtensionNPN = gets stExtensionNPN

setNegotiatedProtocol :: B.ByteString -> TLSSt ()
setNegotiatedProtocol s = modify (\st -> st { stNegotiatedProtocol = Just s })

getNegotiatedProtocol :: TLSSt (Maybe B.ByteString)
getNegotiatedProtocol = gets stNegotiatedProtocol

setServerNextProtocolSuggest :: [B.ByteString] -> TLSSt ()
setServerNextProtocolSuggest ps = modify (\st -> st { stServerNextProtocolSuggest = Just ps})

getServerNextProtocolSuggest :: TLSSt (Maybe [B.ByteString])
getServerNextProtocolSuggest = gets stServerNextProtocolSuggest

setClientCertificateChain :: CertificateChain -> TLSSt ()
setClientCertificateChain s = modify (\st -> st { stClientCertificateChain = Just s })

getClientCertificateChain :: TLSSt (Maybe CertificateChain)
getClientCertificateChain = gets stClientCertificateChain

getVerifiedData :: Role -> TLSSt Bytes
getVerifiedData client = gets (if client == ClientRole then stClientVerifiedData else stServerVerifiedData)

isClientContext :: TLSSt Role
isClientContext = gets stClientContext

genRandom :: Int -> TLSSt Bytes
genRandom n = do
    st <- get
    case withTLSRNG (stRandomGen st) (cprgGenerate n) of
            (bytes, rng') -> put (st { stRandomGen = rng' }) >> return bytes

withRNG :: (forall g . CPRG g => g -> (a, g)) -> TLSSt a
withRNG f = do
    st <- get
    let (a,rng') = withTLSRNG (stRandomGen st) f
    put (st { stRandomGen = rng' })
    return a
