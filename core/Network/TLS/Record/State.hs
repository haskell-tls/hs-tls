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
    , incrRecordState
    , RecordM
    , runRecordM
    , getRecordVersion
    , setRecordIV
    , withCompression
    , computeDigest
    , makeDigest
    , getBulk
    , getMacSequence
    ) where

import Data.Word
import Control.Applicative
import Control.Monad.State
import Network.TLS.Compression
import Network.TLS.Cipher
import Network.TLS.ErrT
import Network.TLS.Struct
import Network.TLS.Wire

import Network.TLS.Packet
import Network.TLS.MAC
import Network.TLS.Util

import qualified Data.ByteString as B

data CryptState = CryptState
    { cstKey        :: !BulkState
    , cstIV         :: !Bytes
    , cstMacSecret  :: !Bytes
    } deriving (Show)

newtype MacState = MacState
    { msSequence :: Word64
    } deriving (Show)

data RecordState = RecordState
    { stCipher      :: Maybe Cipher
    , stCompression :: Compression
    , stCryptState  :: !CryptState
    , stMacState    :: !MacState
    } deriving (Show)

newtype RecordM a = RecordM { runRecordM :: Version
                                         -> RecordState
                                         -> Either TLSError (a, RecordState) }

instance Applicative RecordM where
    pure = return
    (<*>) = ap

instance Monad RecordM where
    return a  = RecordM $ \_ st  -> Right (a, st)
    m1 >>= m2 = RecordM $ \ver st -> do
                    case runRecordM m1 ver st of
                        Left err       -> Left err
                        Right (a, st2) -> runRecordM (m2 a) ver st2

instance Functor RecordM where
    fmap f m = RecordM $ \ver st ->
                case runRecordM m ver st of
                    Left err       -> Left err
                    Right (a, st2) -> Right (f a, st2)

getRecordVersion :: RecordM Version
getRecordVersion = RecordM $ \ver st -> Right (ver, st)

instance MonadState RecordState RecordM where
    put x = RecordM $ \_  _  -> Right ((), x)
    get   = RecordM $ \_  st -> Right (st, st)
#if MIN_VERSION_mtl(2,1,0)
    state f = RecordM $ \_ st -> Right (f st)
#endif

instance MonadError TLSError RecordM where
    throwError e   = RecordM $ \_ _ -> Left e
    catchError m f = RecordM $ \ver st ->
                        case runRecordM m ver st of
                            Left err -> runRecordM (f err) ver st
                            r        -> r

newRecordState :: RecordState
newRecordState = RecordState
    { stCipher      = Nothing
    , stCompression = nullCompression
    , stCryptState  = CryptState BulkStateUninitialized B.empty B.empty
    , stMacState    = MacState 0
    }

incrRecordState :: RecordState -> RecordState
incrRecordState ts = ts { stMacState = MacState (ms + 1) }
  where (MacState ms) = stMacState ts

setRecordIV :: Bytes -> RecordState -> RecordState
setRecordIV iv st = st { stCryptState = (stCryptState st) { cstIV = iv } }

withCompression :: (Compression -> (Compression, a)) -> RecordM a
withCompression f = do
    st <- get
    let (nc, a) = f $ stCompression st
    put $ st { stCompression = nc }
    return a

computeDigest :: Version -> RecordState -> Header -> Bytes -> (Bytes, RecordState)
computeDigest ver tstate hdr content = (digest, incrRecordState tstate)
  where digest = macF (cstMacSecret cst) msg
        cst    = stCryptState tstate
        cipher = fromJust "cipher" $ stCipher tstate
        hashA  = cipherHash cipher
        encodedSeq = encodeWord64 $ msSequence $ stMacState tstate

        (macF, msg)
            | ver < TLS10 = (macSSL hashA, B.concat [ encodedSeq, encodeHeaderNoVer hdr, content ])
            | otherwise   = (hmac hashA, B.concat [ encodedSeq, encodeHeader hdr, content ])

makeDigest :: Header -> Bytes -> RecordM Bytes
makeDigest hdr content = do
    ver <- getRecordVersion
    st <- get
    let (digest, nstate) = computeDigest ver st hdr content
    put nstate
    return digest

getBulk :: RecordM Bulk
getBulk = cipherBulk . fromJust "cipher" . stCipher <$> get

getMacSequence :: RecordM Word64
getMacSequence = msSequence . stMacState <$> get
