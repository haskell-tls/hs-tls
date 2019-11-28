{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CPP #-}

-- | In-memory TLS session manager.
--
-- * Limitation: you can set the maximum size of the session data database.
-- * Automatic pruning: old session data over their lifetime are pruned automatically.
-- * Energy saving: no dedicate pruning thread is running when the size of session data database is zero.
-- * (Replay resistance: each session data is used at most once to prevent replay attacks against 0RTT early data of TLS 1.3.)

module Network.TLS.SessionManager (
    Config(..)
  , defaultConfig
  , newSessionManager
  ) where

import Basement.Block (Block)
import Data.ByteArray (convert)
import Control.Exception (assert)
import Control.Reaper
import Data.ByteString (ByteString)
import Data.IORef
import Data.OrdPSQ (OrdPSQ)
import qualified Data.OrdPSQ as Q
import Network.TLS
#if !MIN_VERSION_tls(1,5,0)
import Network.TLS.Compression
#endif
import qualified System.Clock as C

import Network.TLS.Imports

----------------------------------------------------------------

-- | Configuration for session managers.
data Config = Config {
    -- | Ticket lifetime in seconds.
      ticketLifetime :: !Int
    -- | Pruning delay in seconds. This is set to 'reaperDelay'.
    , pruningDelay   :: !Int
    -- | The limit size of session data entries.
    , dbMaxSize      :: !Int
    }

-- | Lifetime: 1 day , delay: 10 minutes, max size: 1000 entries.
defaultConfig :: Config
defaultConfig = Config {
      ticketLifetime = 86400
    , pruningDelay   = 6000
    , dbMaxSize      = 1000
    }

----------------------------------------------------------------

toKey :: ByteString -> Block Word8
toKey = convert

toValue :: SessionData -> SessionDataCopy
#if MIN_VERSION_tls(1,5,0)
#if MIN_VERSION_tls(1,5,3)
toValue (SessionData v cid comp msni sec mg mti malpn siz flg) =
    SessionDataCopy v cid comp msni sec' mg mti malpn' siz flg
#else
toValue (SessionData v cid comp msni sec mg mti malpn siz) =
    SessionDataCopy v cid comp msni sec' mg mti malpn' siz
#endif
  where
    !sec' = convert sec
    !malpn' = convert <$> malpn
#else
toValue (SessionData v cid comp msni sec) =
    SessionDataCopy v cid comp msni sec'
  where
    !sec' = convert sec
#endif

fromValue :: SessionDataCopy -> SessionData
#if MIN_VERSION_tls(1,5,0)
#if MIN_VERSION_tls(1,5,3)
fromValue (SessionDataCopy v cid comp msni sec' mg mti malpn' siz flg) =
    SessionData v cid comp msni sec mg mti malpn siz flg
#else
fromValue (SessionDataCopy v cid comp msni sec' mg mti malpn' siz) =
    SessionData v cid comp msni sec mg mti malpn siz
#endif
  where
    !sec = convert sec'
    !malpn = convert <$> malpn'
#else
fromValue (SessionDataCopy v cid comp msni sec') =
    SessionData v cid comp msni sec
  where
    !sec = convert sec'
#endif

----------------------------------------------------------------

type SessionIDCopy = Block Word8
data SessionDataCopy = SessionDataCopy
    {- ssVersion     -} !Version
    {- ssCipher      -} !CipherID
    {- ssCompression -} !CompressionID
    {- ssClientSNI   -} !(Maybe HostName)
    {- ssSecret      -} (Block Word8)
#if MIN_VERSION_tls(1,5,0)
    {- ssGroup       -} !(Maybe Group)
    {- ssTicketInfo  -} !(Maybe TLS13TicketInfo)
    {- ssALPN        -} !(Maybe (Block Word8))
    {- ssMaxEarlyDataSize -} Int
#endif
#if MIN_VERSION_tls(1,5,3)
    {- ssFlags       -} [SessionFlag]
#endif
    deriving (Show,Eq)

type Sec = Int64
type Value = (SessionDataCopy, IORef Availability)
type DB = OrdPSQ SessionIDCopy Sec Value
type Item = (SessionIDCopy, Sec, Value, Operation)

data Operation = Add | Del
data Use = SingleUse | MultipleUse
data Availability = Fresh | Used

----------------------------------------------------------------

-- | Creating an in-memory session manager.
newSessionManager :: Config -> IO SessionManager
newSessionManager conf = do
    let lifetime = fromIntegral $ ticketLifetime conf
        maxsiz = dbMaxSize conf
    reaper <- mkReaper defaultReaperSettings {
          reaperEmpty  = Q.empty
        , reaperCons   = cons maxsiz
        , reaperAction = clean
        , reaperNull   = Q.null
        , reaperDelay  = pruningDelay conf * 1000000
        }
    return SessionManager {
        sessionResume         = resume reaper MultipleUse
#if MIN_VERSION_tls(1,5,0)
      , sessionResumeOnlyOnce = resume reaper SingleUse
#endif
      , sessionEstablish      = establish reaper lifetime
      , sessionInvalidate     = invalidate reaper

      }

cons :: Int -> Item -> DB -> DB
cons lim (k,t,v,Add) db
  | lim <= 0            = Q.empty
  | Q.size db == lim    = case Q.minView db of
      Nothing          -> assert False $ Q.insert k t v Q.empty
      Just (_,_,_,db') -> Q.insert k t v db'
  | otherwise           = Q.insert k t v db
cons _   (k,_,_,Del) db = Q.delete k db

clean :: DB -> IO (DB -> DB)
clean olddb = do
    currentTime <- C.sec <$> C.getTime C.Monotonic
    let !pruned = snd $ Q.atMostView currentTime olddb
    return $ merge pruned
  where
    ins db (k,p,v) = Q.insert k p v db
    -- There is not 'merge' API.
    -- We hope that newdb is smaller than pruned.
    merge pruned newdb = foldl' ins pruned entries
      where
        entries = Q.toList newdb

----------------------------------------------------------------

establish :: Reaper DB Item -> Sec
          -> SessionID -> SessionData -> IO ()
establish reaper lifetime k sd = do
    ref <- newIORef Fresh
    !p <- (+ lifetime) . C.sec <$> C.getTime C.Monotonic
    let !v = (sd',ref)
    reaperAdd reaper (k',p,v,Add)
  where
    !k' = toKey k
    !sd' = toValue sd

resume :: Reaper DB Item -> Use
       -> SessionID -> IO (Maybe SessionData)
resume reaper use k = do
    db <- reaperRead reaper
    case Q.lookup k' db of
      Nothing             -> return Nothing
      Just (p,v@(sd,ref)) ->
           case use of
               SingleUse -> do
                   available <- atomicModifyIORef' ref check
                   reaperAdd reaper (k',p,v,Del)
                   return $ if available then Just (fromValue sd) else Nothing
               MultipleUse -> return $ Just (fromValue sd)
  where
    check Fresh = (Used,True)
    check Used  = (Used,False)
    !k' = toKey k

invalidate :: Reaper DB Item
           -> SessionID -> IO ()
invalidate reaper k = do
    db <- reaperRead reaper
    case Q.lookup k' db of
      Nothing    -> return ()
      Just (p,v) -> reaperAdd reaper (k',p,v,Del)
  where
    !k' = toKey k
