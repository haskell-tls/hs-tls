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
    , getLocalPrivateKey
    , getRemotePublicKey
    , setServerDHParams
    , getServerDHParams
    , setServerECDHParams
    , getServerECDHParams
    , setDHPrivate
    , getDHPrivate
    , setECDHPrivate
    , getECDHPrivate
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
    , getPendingCipher
    , setServerHelloParameters
    ) where

import Network.TLS.Util
import Network.TLS.Struct
import Network.TLS.Record.State
import Network.TLS.Packet
import Network.TLS.Crypto
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Types
import Control.Applicative (Applicative, (<$>))
import Control.Monad.State
import Data.X509 (CertificateChain)
import Data.ByteArray (ByteArrayAccess)

data HandshakeKeyState = HandshakeKeyState
    { hksRemotePublicKey :: !(Maybe PubKey)
    , hksLocalPrivateKey :: !(Maybe PrivKey)
    } deriving (Show)

data HandshakeState = HandshakeState
    { hstClientVersion       :: !(Version)
    , hstClientRandom        :: !ClientRandom
    , hstServerRandom        :: !(Maybe ServerRandom)
    , hstMasterSecret        :: !(Maybe Bytes)
    , hstKeyState            :: !HandshakeKeyState
    , hstServerDHParams      :: !(Maybe ServerDHParams)
    , hstDHPrivate           :: !(Maybe DHPrivate)
    , hstServerECDHParams    :: !(Maybe ServerECDHParams)
    , hstECDHPrivate         :: !(Maybe ECDHPrivate)
    , hstHandshakeDigest     :: !(Either [Bytes] HashCtx)
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
    deriving (Functor, Applicative, Monad)

instance MonadState HandshakeState HandshakeM where
    put x = HandshakeM (put x)
    get   = HandshakeM (get)
#if MIN_VERSION_mtl(2,1,0)
    state f = HandshakeM (state f)
#endif

-- create a new empty handshake state
newEmptyHandshake :: Version -> ClientRandom -> HandshakeState
newEmptyHandshake ver crand = HandshakeState
    { hstClientVersion       = ver
    , hstClientRandom        = crand
    , hstServerRandom        = Nothing
    , hstMasterSecret        = Nothing
    , hstKeyState            = HandshakeKeyState Nothing Nothing
    , hstServerDHParams      = Nothing
    , hstDHPrivate           = Nothing
    , hstServerECDHParams    = Nothing
    , hstECDHPrivate         = Nothing
    , hstHandshakeDigest     = Left []
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
setPublicKey pk = modify (\hst -> hst { hstKeyState = setPK (hstKeyState hst) })
  where setPK hks = hks { hksRemotePublicKey = Just pk }

setPrivateKey :: PrivKey -> HandshakeM ()
setPrivateKey pk = modify (\hst -> hst { hstKeyState = setPK (hstKeyState hst) })
  where setPK hks = hks { hksLocalPrivateKey = Just pk }

getRemotePublicKey :: HandshakeM PubKey
getRemotePublicKey = fromJust "remote public key" <$> gets (hksRemotePublicKey . hstKeyState)

getLocalPrivateKey :: HandshakeM PrivKey
getLocalPrivateKey = fromJust "local private key" <$> gets (hksLocalPrivateKey . hstKeyState)

getServerDHParams :: HandshakeM ServerDHParams
getServerDHParams = fromJust "server DH params" <$> gets hstServerDHParams

getServerECDHParams :: HandshakeM ServerECDHParams
getServerECDHParams = fromJust "server ECDH params" <$> gets hstServerECDHParams

setServerDHParams :: ServerDHParams -> HandshakeM ()
setServerDHParams shp = modify (\hst -> hst { hstServerDHParams = Just shp })

setServerECDHParams :: ServerECDHParams -> HandshakeM ()
setServerECDHParams shp = modify (\hst -> hst { hstServerECDHParams = Just shp })

getDHPrivate :: HandshakeM DHPrivate
getDHPrivate = fromJust "server DH private" <$> gets hstDHPrivate

getECDHPrivate :: HandshakeM ECDHPrivate
getECDHPrivate = fromJust "server ECDH private" <$> gets hstECDHPrivate

setDHPrivate :: DHPrivate -> HandshakeM ()
setDHPrivate shp = modify (\hst -> hst { hstDHPrivate = Just shp })

setECDHPrivate :: ECDHPrivate -> HandshakeM ()
setECDHPrivate shp = modify (\hst -> hst { hstECDHPrivate = Just shp })

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

getPendingCipher :: HandshakeM Cipher
getPendingCipher = fromJust "pending cipher" <$> gets hstPendingCipher

addHandshakeMessage :: Bytes -> HandshakeM ()
addHandshakeMessage content = modify $ \hs -> hs { hstHandshakeMessages = content : hstHandshakeMessages hs}

getHandshakeMessages :: HandshakeM [Bytes]
getHandshakeMessages = gets (reverse . hstHandshakeMessages)

updateHandshakeDigest :: Bytes -> HandshakeM ()
updateHandshakeDigest content = modify $ \hs -> hs
    { hstHandshakeDigest = case hstHandshakeDigest hs of
                                Left bytes    -> Left (content:bytes)
                                Right hashCtx -> Right $ hashUpdate hashCtx content }

getHandshakeDigest :: Version -> Role -> HandshakeM Bytes
getHandshakeDigest ver role = gets gen
  where gen hst = case hstHandshakeDigest hst of
                      Right hashCtx ->
                         let msecret = fromJust "master secret" $ hstMasterSecret hst
                             cipher  = fromJust "cipher" $ hstPendingCipher hst
                          in generateFinish ver cipher msecret hashCtx
                      Left _        ->
                         error "un-initialized handshake digest"
        generateFinish | role == ClientRole = generateClientFinished
                       | otherwise          = generateServerFinished

-- | Generate the master secret from the pre master secret.
setMasterSecretFromPre :: ByteArrayAccess preMaster
                       => Version   -- ^ chosen transmission version
                       -> Role      -- ^ the role (Client or Server) of the generating side
                       -> preMaster -- ^ the pre master secret
                       -> HandshakeM ()
setMasterSecretFromPre ver role premasterSecret = do
    secret <- genSecret <$> get
    setMasterSecret ver role secret
  where genSecret hst =
            generateMasterSecret ver (fromJust "cipher" $ hstPendingCipher hst)
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
        digestSize   = if hasMAC (bulkF bulk) then hashDigestSize (cipherHash cipher)
                                              else 0
        keySize      = bulkKeySize bulk
        ivSize       = bulkIVSize bulk
        kb           = generateKeyBlock ver cipher (hstClientRandom hst)
                                        (fromJust "server random" $ hstServerRandom hst)
                                        masterSecret keyblockSize

        (cMACSecret, sMACSecret, cWriteKey, sWriteKey, cWriteIV, sWriteIV) =
                    fromJust "p6" $ partition6 kb (digestSize, digestSize, keySize, keySize, ivSize, ivSize)

        cstClient = CryptState { cstKey        = bulkInit bulk (BulkEncrypt `orOnServer` BulkDecrypt) cWriteKey
                               , cstIV         = cWriteIV
                               , cstMacSecret  = cMACSecret }
        cstServer = CryptState { cstKey        = bulkInit bulk (BulkDecrypt `orOnServer` BulkEncrypt) sWriteKey
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

        orOnServer f g = if cc == ClientRole then f else g


setServerHelloParameters :: Version      -- ^ chosen version
                         -> ServerRandom
                         -> Cipher
                         -> Compression
                         -> HandshakeM ()
setServerHelloParameters ver sran cipher compression = do
    modify $ \hst -> hst
                { hstServerRandom       = Just sran
                , hstPendingCipher      = Just cipher
                , hstPendingCompression = compression
                , hstHandshakeDigest    = updateDigest $ hstHandshakeDigest hst
                }
  where hashAlg = getHash ver cipher
        updateDigest (Left bytes) = Right $ foldl hashUpdate (hashInit hashAlg) $ reverse bytes
        updateDigest (Right _)    = error "cannot initialize digest with another digest"

-- The TLS12 Hash is cipher specific, and some TLS12 algorithms use SHA384
-- instead of the default SHA256.
getHash :: Version -> Cipher -> Hash
getHash ver ciph
    | ver < TLS12                              = SHA1_MD5
    | maybe True (< TLS12) (cipherMinVer ciph) = SHA256
    | otherwise                                = cipherHash ciph
