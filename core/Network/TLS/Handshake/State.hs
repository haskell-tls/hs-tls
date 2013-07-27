{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Network.TLS.Handshake.State
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.State
    ( HandshakeState(..)
    , ClientCertRequestData
    , HandshakeM
    , newEmptyHandshake
    , runHandshake
    -- * key accessors
    , setPublicKey
    , setPrivateKey
    , setClientPublicKey
    , setClientPrivateKey
    -- * cert accessors
    , setClientCertSent
    , getClientCertSent
    , setCertReqSent
    , getCertReqSent
    , setClientCertChain
    , getClientCertChain
    , setClientCertRequest
    , getClientCertRequest
    -- * digest accessors
    , addHandshakeMessage
    , updateHandshakeDigest
    , getHandshakeMessages
    , getHandshakeDigest
    -- * master secret
    , setMasterSecret
    , setMasterSecretFromPre
    -- * misc accessor
    , setPendingAlgs
    , setServerRandom
    ) where

import Network.TLS.Util
import Network.TLS.Struct
import Network.TLS.Record.State
import Network.TLS.Packet
import Network.TLS.Crypto
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Types
import Control.Applicative ((<$>))
import Control.Monad.State
import Data.X509 (CertificateChain)

data HandshakeState = HandshakeState
    { hstClientVersion       :: !(Version)
    , hstClientRandom        :: !ClientRandom
    , hstServerRandom        :: !(Maybe ServerRandom)
    , hstMasterSecret        :: !(Maybe Bytes)
    , hstRSAPublicKey        :: !(Maybe PubKey)
    , hstRSAPrivateKey       :: !(Maybe PrivKey)
    , hstRSAClientPublicKey  :: !(Maybe PubKey)
    , hstRSAClientPrivateKey :: !(Maybe PrivKey)
    , hstHandshakeDigest     :: !HashCtx
    , hstHandshakeMessages   :: [Bytes]
    , hstClientCertRequest   :: !(Maybe ClientCertRequestData) -- ^ Set to Just-value when certificate request was received
    , hstClientCertSent      :: !Bool -- ^ Set to true when a client certificate chain was sent
    , hstCertReqSent         :: !Bool -- ^ Set to true when a certificate request was sent
    , hstClientCertChain     :: !(Maybe CertificateChain)
    , hstPendingTxState      :: Maybe RecordState
    , hstPendingRxState      :: Maybe RecordState
    , hstPendingCipher       :: Maybe Cipher
    , hstPendingCompression  :: Compression
    } deriving (Show)

type ClientCertRequestData = ([CertificateType],
                              Maybe [(HashAlgorithm, SignatureAlgorithm)],
                              [DistinguishedName])
  

newtype HandshakeM a = HandshakeM { runHandshakeM :: State HandshakeState a }
    deriving (Functor, Monad)

instance MonadState HandshakeState HandshakeM where
    put x = HandshakeM (put x)
    get   = HandshakeM (get)
#if MIN_VERSION_mtl(2,1,0)
    state f = HandshakeM (state f)
#endif

-- create a new empty handshake state
newEmptyHandshake :: Version -> ClientRandom -> HashCtx -> HandshakeState
newEmptyHandshake ver crand digestInit = HandshakeState
    { hstClientVersion       = ver
    , hstClientRandom        = crand
    , hstServerRandom        = Nothing
    , hstMasterSecret        = Nothing
    , hstRSAPublicKey        = Nothing
    , hstRSAPrivateKey       = Nothing
    , hstRSAClientPublicKey  = Nothing
    , hstRSAClientPrivateKey = Nothing
    , hstHandshakeDigest     = digestInit
    , hstHandshakeMessages   = []
    , hstClientCertRequest   = Nothing
    , hstClientCertSent      = False
    , hstCertReqSent         = False
    , hstClientCertChain     = Nothing
    , hstPendingTxState      = Nothing
    , hstPendingRxState      = Nothing
    , hstPendingCipher       = Nothing
    , hstPendingCompression  = nullCompression
    }

runHandshake :: HandshakeState -> HandshakeM a -> (a, HandshakeState)
runHandshake hst f = runState (runHandshakeM f) hst

setPublicKey :: PubKey -> HandshakeM ()
setPublicKey pk = modify (\hst -> hst { hstRSAPublicKey = Just pk })

setPrivateKey :: PrivKey -> HandshakeM ()
setPrivateKey pk = modify (\hst -> hst { hstRSAPrivateKey = Just pk })

setClientPublicKey :: PubKey -> HandshakeM ()
setClientPublicKey pk = modify (\hst -> hst { hstRSAClientPublicKey = Just pk })

setClientPrivateKey :: PrivKey -> HandshakeM ()
setClientPrivateKey pk = modify (\hst -> hst { hstRSAClientPrivateKey = Just pk })

setCertReqSent :: Bool -> HandshakeM ()
setCertReqSent b = modify (\hst -> hst { hstCertReqSent = b })

getCertReqSent :: HandshakeM Bool
getCertReqSent = gets hstCertReqSent

setClientCertSent :: Bool -> HandshakeM ()
setClientCertSent b = modify (\hst -> hst { hstClientCertSent = b })

getClientCertSent :: HandshakeM Bool
getClientCertSent = gets hstClientCertSent

setClientCertChain :: CertificateChain -> HandshakeM ()
setClientCertChain b = modify (\hst -> hst { hstClientCertChain = Just b })

getClientCertChain :: HandshakeM (Maybe CertificateChain)
getClientCertChain = gets hstClientCertChain

setClientCertRequest :: ClientCertRequestData -> HandshakeM ()
setClientCertRequest d = modify (\hst -> hst { hstClientCertRequest = Just d })

getClientCertRequest :: HandshakeM (Maybe ClientCertRequestData)
getClientCertRequest = gets hstClientCertRequest

addHandshakeMessage :: Bytes -> HandshakeM ()
addHandshakeMessage content = modify $ \hs -> hs { hstHandshakeMessages = content : hstHandshakeMessages hs}

getHandshakeMessages :: HandshakeM [Bytes]
getHandshakeMessages = gets (reverse . hstHandshakeMessages)

updateHandshakeDigest :: Bytes -> HandshakeM ()
updateHandshakeDigest content = modify $ \hs -> hs { hstHandshakeDigest = hashUpdate (hstHandshakeDigest hs) content }

getHandshakeDigest :: Version -> Role -> HandshakeM Bytes
getHandshakeDigest ver role = gets gen
  where gen hst = let hashctx = hstHandshakeDigest hst
                      msecret = fromJust "master secret" $ hstMasterSecret hst
                   in generateFinish ver msecret hashctx
        generateFinish | role == ClientRole = generateClientFinished
                       | otherwise          = generateServerFinished

setMasterSecretFromPre :: Version -> Role -> Bytes -> HandshakeM ()
setMasterSecretFromPre ver role premasterSecret = do
    secret <- genSecret <$> get
    setMasterSecret ver role secret
  where genSecret hst = generateMasterSecret ver
                                 premasterSecret
                                 (hstClientRandom hst)
                                 (fromJust "server random" $ hstServerRandom hst)

-- | Set master secret and as a side effect generate the key block
-- with all the right parameters, and setup the pending tx/rx state.
setMasterSecret :: Version -> Role -> Bytes -> HandshakeM ()
setMasterSecret ver role masterSecret = modify $ \hst ->
    let (pendingTx, pendingRx) = computeKeyBlock hst masterSecret ver role
     in hst { hstMasterSecret   = Just masterSecret
            , hstPendingTxState = Just pendingTx
            , hstPendingRxState = Just pendingRx }

computeKeyBlock :: HandshakeState -> Bytes -> Version -> Role -> (RecordState, RecordState)
computeKeyBlock hst masterSecret ver cc = (pendingTx, pendingRx)
  where cipher       = fromJust "cipher" $ hstPendingCipher hst
        keyblockSize = cipherKeyBlockSize cipher

        bulk         = cipherBulk cipher
        digestSize   = hashSize $ cipherHash cipher
        keySize      = bulkKeySize bulk
        ivSize       = bulkIVSize bulk
        kb           = generateKeyBlock ver (hstClientRandom hst)
                                        (fromJust "server random" $ hstServerRandom hst)
                                        masterSecret keyblockSize

        (cMACSecret, sMACSecret, cWriteKey, sWriteKey, cWriteIV, sWriteIV) =
                    fromJust "p6" $ partition6 kb (digestSize, digestSize, keySize, keySize, ivSize, ivSize)

        cstClient = CryptState { cstKey        = cWriteKey
                               , cstIV         = cWriteIV
                               , cstMacSecret  = cMACSecret }
        cstServer = CryptState { cstKey        = sWriteKey
                               , cstIV         = sWriteIV
                               , cstMacSecret  = sMACSecret }
        msClient = MacState { msSequence = 0 }
        msServer = MacState { msSequence = 0 }

        pendingTx = RecordState
                  { stCryptState  = if cc == ClientRole then cstClient else cstServer
                  , stMacState    = if cc == ClientRole then msClient else msServer
                  , stCipher      = Just cipher
                  , stCompression = hstPendingCompression hst
                  }
        pendingRx = RecordState
                  { stCryptState  = if cc == ClientRole then cstServer else cstClient
                  , stMacState    = if cc == ClientRole then msServer else msClient
                  , stCipher      = Just cipher
                  , stCompression = hstPendingCompression hst
                  }

setPendingAlgs :: Cipher -> Compression -> HandshakeM ()
setPendingAlgs cipher compression =
    modify $ \hst -> hst { hstPendingCipher = Just cipher, hstPendingCompression = compression }

setServerRandom :: ServerRandom -> HandshakeM ()
setServerRandom ran = modify $ \hst -> hst { hstServerRandom = Just ran }
