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
    , CryptLevel(..)
    , HasCryptLevel(..)
    , MacState(..)
    , RecordOptions(..)
    , RecordState(..)
    , newRecordState
    , incrRecordState
    , RecordM
    , runRecordM
    , getRecordOptions
    , getRecordVersion
    , setRecordIV
    , withCompression
    , computeDigest
    , makeDigest
    , getBulk
    , getMacSequence
    ) where

import Control.Monad.State.Strict
import Network.TLS.Compression
import Network.TLS.Cipher
import Network.TLS.ErrT
import Network.TLS.Struct
import Network.TLS.Wire

import Network.TLS.Packet
import Network.TLS.MAC
import Network.TLS.Util
import Network.TLS.Imports
import Network.TLS.Types

import qualified Data.ByteString as B

data CryptState = CryptState
    { cstKey        :: !BulkState
    , cstIV         :: !ByteString
    -- In TLS 1.2 or earlier, this holds mac secret.
    -- In TLS 1.3, this holds application traffic secret N.
    , cstMacSecret  :: !ByteString
    } deriving (Show)

newtype MacState = MacState
    { msSequence :: Word64
    } deriving (Show)

data RecordOptions = RecordOptions
    { recordVersion :: Version                -- version to use when sending/receiving
    , recordTLS13 :: Bool                     -- TLS13 record processing
    }

-- | TLS encryption level.
data CryptLevel
    = CryptInitial            -- ^ Unprotected traffic
    | CryptMasterSecret       -- ^ Protected with master secret (TLS < 1.3)
    | CryptEarlySecret        -- ^ Protected with early traffic secret (TLS 1.3)
    | CryptHandshakeSecret    -- ^ Protected with handshake traffic secret (TLS 1.3)
    | CryptApplicationSecret  -- ^ Protected with application traffic secret (TLS 1.3)
    deriving (Eq,Show)

class HasCryptLevel a where getCryptLevel :: proxy a -> CryptLevel
instance HasCryptLevel EarlySecret where getCryptLevel _ = CryptEarlySecret
instance HasCryptLevel HandshakeSecret where getCryptLevel _ = CryptHandshakeSecret
instance HasCryptLevel ApplicationSecret where getCryptLevel _ = CryptApplicationSecret

data RecordState = RecordState
    { stCipher      :: Maybe Cipher
    , stCompression :: Compression
    , stCryptLevel  :: !CryptLevel
    , stCryptState  :: !CryptState
    , stMacState    :: !MacState
    } deriving (Show)

newtype RecordM a = RecordM { runRecordM :: RecordOptions
                                         -> RecordState
                                         -> Either TLSError (a, RecordState) }

instance Applicative RecordM where
    pure = return
    (<*>) = ap

instance Monad RecordM where
    return a  = RecordM $ \_ st  -> Right (a, st)
    m1 >>= m2 = RecordM $ \opt st ->
                    case runRecordM m1 opt st of
                        Left err       -> Left err
                        Right (a, st2) -> runRecordM (m2 a) opt st2

instance Functor RecordM where
    fmap f m = RecordM $ \opt st ->
                case runRecordM m opt st of
                    Left err       -> Left err
                    Right (a, st2) -> Right (f a, st2)

getRecordOptions :: RecordM RecordOptions
getRecordOptions = RecordM $ \opt st -> Right (opt, st)

getRecordVersion :: RecordM Version
getRecordVersion = recordVersion <$> getRecordOptions

instance MonadState RecordState RecordM where
    put x = RecordM $ \_  _  -> Right ((), x)
    get   = RecordM $ \_  st -> Right (st, st)
#if MIN_VERSION_mtl(2,1,0)
    state f = RecordM $ \_ st -> Right (f st)
#endif

instance MonadError TLSError RecordM where
    throwError e   = RecordM $ \_ _ -> Left e
    catchError m f = RecordM $ \opt st ->
                        case runRecordM m opt st of
                            Left err -> runRecordM (f err) opt st
                            r        -> r

newRecordState :: RecordState
newRecordState = RecordState
    { stCipher      = Nothing
    , stCompression = nullCompression
    , stCryptLevel  = CryptInitial
    , stCryptState  = CryptState BulkStateUninitialized B.empty B.empty
    , stMacState    = MacState 0
    }

incrRecordState :: RecordState -> RecordState
incrRecordState ts = ts { stMacState = MacState (ms + 1) }
  where (MacState ms) = stMacState ts

setRecordIV :: ByteString -> RecordState -> RecordState
setRecordIV iv st = st { stCryptState = (stCryptState st) { cstIV = iv } }

withCompression :: (Compression -> (Compression, a)) -> RecordM a
withCompression f = do
    st <- get
    let (nc, a) = f $ stCompression st
    put $ st { stCompression = nc }
    return a

computeDigest :: Version -> RecordState -> Header -> ByteString -> (ByteString, RecordState)
computeDigest ver tstate hdr content = (digest, incrRecordState tstate)
  where digest = macF (cstMacSecret cst) msg
        cst    = stCryptState tstate
        cipher = fromJust "cipher" $ stCipher tstate
        hashA  = cipherHash cipher
        encodedSeq = encodeWord64 $ msSequence $ stMacState tstate

        (macF, msg)
            | ver < TLS10 = (macSSL hashA, B.concat [ encodedSeq, encodeHeaderNoVer hdr, content ])
            | otherwise   = (hmac hashA, B.concat [ encodedSeq, encodeHeader hdr, content ])

makeDigest :: Header -> ByteString -> RecordM ByteString
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
