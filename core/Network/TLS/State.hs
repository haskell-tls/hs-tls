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
    , setExtensionALPN
    , getExtensionALPN
    , setNegotiatedProtocol
    , getNegotiatedProtocol
    , setClientALPNSuggest
    , getClientALPNSuggest
    , setClientEcPointFormatSuggest
    , getClientEcPointFormatSuggest
    , getClientCertificateChain
    , setClientCertificateChain
    , setClientSNI
    , getClientSNI
    , getVerifiedData
    , setSession
    , getSession
    , isSessionResuming
    , isClientContext
    , setExporterMasterSecret
    , getExporterMasterSecret
    , setTLS13KeyShare
    , getTLS13KeyShare
    , setTLS13PreSharedKey
    , getTLS13PreSharedKey
    , setTLS13HRR
    , getTLS13HRR
    , setTLS13Cookie
    , getTLS13Cookie
    , setClientSupportsPHA
    , getClientSupportsPHA
    -- * random
    , genRandom
    , withRNG
    ) where

import Network.TLS.Imports
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.RNG
import Network.TLS.Types (Role(..), HostName)
import Network.TLS.Wire (GetContinuation)
import Network.TLS.Extension
import qualified Data.ByteString as B
import Control.Monad.State.Strict
import Network.TLS.ErrT
import Crypto.Random
import Data.X509 (CertificateChain)

data TLSState = TLSState
    { stSession             :: Session
    , stSessionResuming     :: Bool
    , stSecureRenegotiation :: Bool  -- RFC 5746
    , stClientVerifiedData  :: ByteString -- RFC 5746
    , stServerVerifiedData  :: ByteString -- RFC 5746
    , stExtensionALPN       :: Bool  -- RFC 7301
    , stHandshakeRecordCont :: Maybe (GetContinuation (HandshakeType, ByteString))
    , stNegotiatedProtocol  :: Maybe B.ByteString -- ALPN protocol
    , stHandshakeRecordCont13 :: Maybe (GetContinuation (HandshakeType13, ByteString))
    , stClientALPNSuggest   :: Maybe [B.ByteString]
    , stClientGroupSuggest  :: Maybe [Group]
    , stClientEcPointFormatSuggest :: Maybe [EcPointFormat]
    , stClientCertificateChain :: Maybe CertificateChain
    , stClientSNI           :: Maybe HostName
    , stRandomGen           :: StateRNG
    , stVersion             :: Maybe Version
    , stClientContext       :: Role
    , stTLS13KeyShare       :: Maybe KeyShare
    , stTLS13PreSharedKey   :: Maybe PreSharedKey
    , stTLS13HRR            :: !Bool
    , stTLS13Cookie         :: Maybe Cookie
    , stExporterMasterSecret :: Maybe ByteString -- TLS 1.3
    , stClientSupportsPHA   :: !Bool -- Post-Handshake Authentication (TLS 1.3)
    }

newtype TLSSt a = TLSSt { runTLSSt :: ErrT TLSError (State TLSState) a }
    deriving (Monad, MonadError TLSError, Functor, Applicative)

instance MonadState TLSState TLSSt where
    put x = TLSSt (lift $ put x)
    get   = TLSSt (lift get)
#if MIN_VERSION_mtl(2,1,0)
    state f = TLSSt (lift $ state f)
#endif

runTLSState :: TLSSt a -> TLSState -> (Either TLSError a, TLSState)
runTLSState f st = runState (runErrT (runTLSSt f)) st

newTLSState :: StateRNG -> Role -> TLSState
newTLSState rng clientContext = TLSState
    { stSession             = Session Nothing
    , stSessionResuming     = False
    , stSecureRenegotiation = False
    , stClientVerifiedData  = B.empty
    , stServerVerifiedData  = B.empty
    , stExtensionALPN       = False
    , stHandshakeRecordCont = Nothing
    , stHandshakeRecordCont13 = Nothing
    , stNegotiatedProtocol  = Nothing
    , stClientALPNSuggest   = Nothing
    , stClientGroupSuggest  = Nothing
    , stClientEcPointFormatSuggest = Nothing
    , stClientCertificateChain = Nothing
    , stClientSNI           = Nothing
    , stRandomGen           = rng
    , stVersion             = Nothing
    , stClientContext       = clientContext
    , stTLS13KeyShare       = Nothing
    , stTLS13PreSharedKey   = Nothing
    , stTLS13HRR            = False
    , stTLS13Cookie         = Nothing
    , stExporterMasterSecret = Nothing
    , stClientSupportsPHA   = False
    }

updateVerifiedData :: Role -> ByteString -> TLSSt ()
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
getVersion = fromMaybe (error "internal error: version hasn't been set yet") <$> gets stVersion

getVersionWithDefault :: Version -> TLSSt Version
getVersionWithDefault defaultVer = fromMaybe defaultVer <$> gets stVersion

setSecureRenegotiation :: Bool -> TLSSt ()
setSecureRenegotiation b = modify (\st -> st { stSecureRenegotiation = b })

getSecureRenegotiation :: TLSSt Bool
getSecureRenegotiation = gets stSecureRenegotiation

setExtensionALPN :: Bool -> TLSSt ()
setExtensionALPN b = modify (\st -> st { stExtensionALPN = b })

getExtensionALPN :: TLSSt Bool
getExtensionALPN = gets stExtensionALPN

setNegotiatedProtocol :: B.ByteString -> TLSSt ()
setNegotiatedProtocol s = modify (\st -> st { stNegotiatedProtocol = Just s })

getNegotiatedProtocol :: TLSSt (Maybe B.ByteString)
getNegotiatedProtocol = gets stNegotiatedProtocol

setClientALPNSuggest :: [B.ByteString] -> TLSSt ()
setClientALPNSuggest ps = modify (\st -> st { stClientALPNSuggest = Just ps})

getClientALPNSuggest :: TLSSt (Maybe [B.ByteString])
getClientALPNSuggest = gets stClientALPNSuggest

setClientEcPointFormatSuggest :: [EcPointFormat] -> TLSSt ()
setClientEcPointFormatSuggest epf = modify (\st -> st { stClientEcPointFormatSuggest = Just epf})

getClientEcPointFormatSuggest :: TLSSt (Maybe [EcPointFormat])
getClientEcPointFormatSuggest = gets stClientEcPointFormatSuggest

setClientCertificateChain :: CertificateChain -> TLSSt ()
setClientCertificateChain s = modify (\st -> st { stClientCertificateChain = Just s })

getClientCertificateChain :: TLSSt (Maybe CertificateChain)
getClientCertificateChain = gets stClientCertificateChain

setClientSNI :: HostName -> TLSSt ()
setClientSNI hn = modify (\st -> st { stClientSNI = Just hn })

getClientSNI :: TLSSt (Maybe HostName)
getClientSNI = gets stClientSNI

getVerifiedData :: Role -> TLSSt ByteString
getVerifiedData client = gets (if client == ClientRole then stClientVerifiedData else stServerVerifiedData)

isClientContext :: TLSSt Role
isClientContext = gets stClientContext

genRandom :: Int -> TLSSt ByteString
genRandom n = do
    withRNG (getRandomBytes n)

withRNG :: MonadPseudoRandom StateRNG a -> TLSSt a
withRNG f = do
    st <- get
    let (a,rng') = withTLSRNG (stRandomGen st) f
    put (st { stRandomGen = rng' })
    return a

setExporterMasterSecret :: ByteString -> TLSSt ()
setExporterMasterSecret key = modify (\st -> st { stExporterMasterSecret = Just key })

getExporterMasterSecret :: TLSSt (Maybe ByteString)
getExporterMasterSecret = gets stExporterMasterSecret

setTLS13KeyShare :: Maybe KeyShare -> TLSSt ()
setTLS13KeyShare mks = modify (\st -> st { stTLS13KeyShare = mks })

getTLS13KeyShare :: TLSSt (Maybe KeyShare)
getTLS13KeyShare = gets stTLS13KeyShare

setTLS13PreSharedKey :: Maybe PreSharedKey -> TLSSt ()
setTLS13PreSharedKey mpsk = modify (\st -> st { stTLS13PreSharedKey = mpsk })

getTLS13PreSharedKey :: TLSSt (Maybe PreSharedKey)
getTLS13PreSharedKey = gets stTLS13PreSharedKey

setTLS13HRR :: Bool -> TLSSt ()
setTLS13HRR b = modify (\st -> st { stTLS13HRR = b })

getTLS13HRR :: TLSSt Bool
getTLS13HRR = gets stTLS13HRR

setTLS13Cookie :: Maybe Cookie -> TLSSt ()
setTLS13Cookie mcookie = modify (\st -> st { stTLS13Cookie = mcookie })

getTLS13Cookie :: TLSSt (Maybe Cookie)
getTLS13Cookie = gets stTLS13Cookie

setClientSupportsPHA :: Bool -> TLSSt ()
setClientSupportsPHA b = modify (\st -> st { stClientSupportsPHA = b })

getClientSupportsPHA :: TLSSt Bool
getClientSupportsPHA = gets stClientSupportsPHA
