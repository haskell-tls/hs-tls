{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Network.TLS.Record.State
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Record.State
    ( CryptState(..)
    , MacState(..)
    , TransmissionState(..)
    , RecordState(..)
    , newRecordState
    , RecordM(..)
    , withTxCompression
    , withRxCompression
    , modifyTxState
    , modifyRxState
    , modifyTxState_
    , modifyRxState_
    , genTLSRandom
    , computeDigest
    , makeDigest
    ) where

import Data.Word
import Crypto.Random.API
import Control.Monad.State
import Control.Monad.Error
import Network.TLS.Compression
import Network.TLS.RNG
import Network.TLS.Cipher
import Network.TLS.Struct
import Network.TLS.Wire

import Network.TLS.Packet
import Network.TLS.MAC
import Network.TLS.Util
import Network.TLS.Types (Role(..))

import qualified Data.ByteString as B

data CryptState = CryptState
    { cstKey        :: !Bytes
    , cstIV         :: !Bytes
    , cstMacSecret  :: !Bytes
    } deriving (Show)

newtype MacState = MacState
    { msSequence :: Word64
    } deriving (Show)

data TransmissionState = TransmissionState
    { stCipher      :: Maybe Cipher
    , stCompression :: Compression
    , stCryptState  :: !CryptState
    , stMacState    :: !MacState
    } deriving (Show)

data RecordState = RecordState
    { stClientContext       :: Role
    , stVersion             :: !Version
    , stTxState             :: TransmissionState
    , stRxState             :: TransmissionState
    , stRandomGen           :: StateRNG
    } deriving (Show)

newtype RecordM a = RecordM { runRecordM :: ErrorT TLSError (State RecordState) a }
    deriving (Monad, MonadError TLSError)

instance Functor RecordM where
    fmap f = RecordM . fmap f . runRecordM

instance MonadState RecordState RecordM where
    put x = RecordM (lift $ put x)
    get   = RecordM (lift get)
#if MIN_VERSION_mtl(2,1,0)
    state f = RecordM (lift $ state f)
#endif

newTransmissionState :: TransmissionState
newTransmissionState = TransmissionState
    { stCipher      = Nothing
    , stCompression = nullCompression
    , stCryptState  = CryptState B.empty B.empty B.empty
    , stMacState    = MacState 0
    }

incrTransmissionState :: TransmissionState -> TransmissionState
incrTransmissionState ts = ts { stMacState = MacState (ms + 1) }
  where (MacState ms) = stMacState ts

newRecordState :: CPRG g => g -> Role -> RecordState
newRecordState rng clientContext = RecordState
    { stClientContext       = clientContext
    , stVersion             = TLS10
    , stTxState             = newTransmissionState
    , stRxState             = newTransmissionState
    , stRandomGen           = StateRNG rng
    }

modifyTxState :: (TransmissionState -> (TransmissionState, a)) -> RecordM a
modifyTxState f =
    get >>= \st -> case f $ stTxState st of
                    (nst, a) -> put (st { stTxState = nst }) >> return a

modifyTxState_ :: (TransmissionState -> TransmissionState) -> RecordM ()
modifyTxState_ f = modifyTxState (\t -> (f t, ()))

modifyRxState :: (TransmissionState -> (TransmissionState, a)) -> RecordM a
modifyRxState f =
    get >>= \st -> case f $ stRxState st of
                    (nst, a) -> put (st { stRxState = nst }) >> return a

modifyRxState_ :: (TransmissionState -> TransmissionState) -> RecordM ()
modifyRxState_ f = modifyRxState (\t -> (f t, ()))

modifyCompression :: TransmissionState -> (Compression -> (Compression, a)) -> (TransmissionState, a)
modifyCompression tst f = case f (stCompression tst) of
                            (nc, a) -> (tst { stCompression = nc }, a)

withTxCompression :: (Compression -> (Compression, a)) -> RecordM a
withTxCompression f = modifyTxState $ \tst -> modifyCompression tst f

withRxCompression :: (Compression -> (Compression, a)) -> RecordM a
withRxCompression f = modifyRxState $ \tst -> modifyCompression tst f

genTLSRandom :: Int -> RecordM Bytes
genTLSRandom n = do
    st <- get
    case withTLSRNG (stRandomGen st) (genRandomBytes n) of
            (bytes, rng') -> put (st { stRandomGen = rng' }) >> return bytes

computeDigest :: Version -> TransmissionState -> Header -> Bytes -> (Bytes, TransmissionState)
computeDigest ver tstate hdr content = (digest, incrTransmissionState tstate)
  where digest = macF (cstMacSecret cst) msg
        cst    = stCryptState tstate
        cipher = fromJust "cipher" $ stCipher tstate
        hashf  = hashF $ cipherHash cipher
        encodedSeq = encodeWord64 $ msSequence $ stMacState tstate

        (macF, msg)
            | ver < TLS10 = (macSSL hashf, B.concat [ encodedSeq, encodeHeaderNoVer hdr, content ])
            | otherwise   = (hmac hashf 64, B.concat [ encodedSeq, encodeHeader hdr, content ])

makeDigest :: Bool -> Header -> Bytes -> RecordM Bytes
makeDigest w hdr content = do
    st <- get
    let (digest, nstate) = computeDigest (stVersion st)
                                         (if w then stTxState st else stRxState st) hdr content
    put $ if w
            then st { stTxState = nstate }
            else st { stRxState = nstate }
    return digest
