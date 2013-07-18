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
    , RecordState(..)
    , newRecordState
    , RecordM(..)
    , withTxCompression
    , withRxCompression
    , genTLSRandom
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

import qualified Data.ByteString as B

data CryptState = CryptState
    { cstKey        :: !Bytes
    , cstIV         :: !Bytes
    , cstMacSecret  :: !Bytes
    } deriving (Show)

newtype MacState = MacState
    { msSequence :: Word64
    } deriving (Show)

type TLSCryptState = CryptState
type TLSMacState = MacState
data RecordState = RecordState
    { stClientContext       :: Bool
    , stVersion             :: !Version
    , stTxEncrypted         :: Bool
    , stRxEncrypted         :: Bool
    , stActiveTxCryptState  :: !(Maybe TLSCryptState)
    , stActiveRxCryptState  :: !(Maybe TLSCryptState)
    , stPendingTxCryptState :: !(Maybe TLSCryptState)
    , stPendingRxCryptState :: !(Maybe TLSCryptState)
    , stActiveTxMacState    :: !(Maybe TLSMacState)
    , stActiveRxMacState    :: !(Maybe TLSMacState)
    , stPendingTxMacState   :: !(Maybe TLSMacState)
    , stPendingRxMacState   :: !(Maybe TLSMacState)
    , stActiveTxCipher      :: Maybe Cipher
    , stActiveRxCipher      :: Maybe Cipher
    , stPendingCipher       :: Maybe Cipher
    , stTxCompression       :: Compression
    , stRxCompression       :: Compression
    , stPendingCompression  :: Compression
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

newRecordState :: CPRG g => g -> Bool -> RecordState
newRecordState rng clientContext = RecordState
    { stClientContext       = clientContext
    , stVersion             = TLS10
    , stTxEncrypted         = False
    , stRxEncrypted         = False
    , stActiveTxCryptState  = Nothing
    , stActiveRxCryptState  = Nothing
    , stPendingTxCryptState = Nothing
    , stPendingRxCryptState = Nothing
    , stActiveTxMacState    = Nothing
    , stActiveRxMacState    = Nothing
    , stPendingTxMacState   = Nothing
    , stPendingRxMacState   = Nothing
    , stActiveTxCipher      = Nothing
    , stActiveRxCipher      = Nothing
    , stPendingCipher       = Nothing
    , stTxCompression       = nullCompression
    , stRxCompression       = nullCompression
    , stPendingCompression  = nullCompression
    , stRandomGen           = StateRNG rng
    }

withTxCompression :: (Compression -> (Compression, a)) -> RecordM a
withTxCompression f = do
    st <- get
    let (nc, a) = f (stTxCompression st)
    put $ st { stTxCompression = nc }
    return a

withRxCompression :: (Compression -> (Compression, a)) -> RecordM a
withRxCompression f = do
    st <- get
    let (nc, a) = f (stRxCompression st)
    put $ st { stRxCompression = nc }
    return a

genTLSRandom :: Int -> RecordM Bytes
genTLSRandom n = do
    st <- get
    case withTLSRNG (stRandomGen st) (genRandomBytes n) of
            (bytes, rng') -> put (st { stRandomGen = rng' }) >> return bytes

makeDigest :: Bool -> Header -> Bytes -> RecordM Bytes
makeDigest w hdr content = do
    st <- get
    let ver = stVersion st
    let cst = fromJust "crypt state" $ if w then stActiveTxCryptState st else stActiveRxCryptState st
    let ms = fromJust "mac state" $ if w then stActiveTxMacState st else stActiveRxMacState st
    let cipher = fromJust "cipher" $ if w then stActiveTxCipher st else stActiveRxCipher st
    let hashf = hashF $ cipherHash cipher

    let (macF, msg) =
            if ver < TLS10
                then (macSSL hashf, B.concat [ encodeWord64 $ msSequence ms, encodeHeaderNoVer hdr, content ])
                else (hmac hashf 64, B.concat [ encodeWord64 $ msSequence ms, encodeHeader hdr, content ])
    let digest = macF (cstMacSecret cst) msg

    let newms = ms { msSequence = (msSequence ms) + 1 }

    put (if w then st { stActiveTxMacState = Just newms } else st { stActiveRxMacState = Just newms })
    return digest
