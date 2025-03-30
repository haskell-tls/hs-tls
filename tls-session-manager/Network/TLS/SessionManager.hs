-- | In-memory TLS 1.2/1.3 session manager.
--
-- * Limitation: you can set the maximum size of the session data database.
-- * Automatic pruning: old session data over their lifetime are pruned automatically.
-- * Energy saving: no dedicate pruning thread is running when the size of session data database is zero.
-- * Replay resistance: each session data is used at most once to prevent replay attacks against 0RTT early data of TLS 1.3.
module Network.TLS.SessionManager (
    newSessionManager,
    Config,
    defaultConfig,
    ticketLifetime,
    pruningDelay,
    dbMaxSize,
) where

import Control.Exception (assert)
import Control.Reaper
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as SBS
import Data.IORef
import Data.OrdPSQ (OrdPSQ)
import qualified Data.OrdPSQ as Q
import Network.TLS
import qualified System.Clock as C

import Network.TLS.Imports

----------------------------------------------------------------

-- | Configuration for session managers.
data Config = Config
    { ticketLifetime :: Int
    -- ^ Ticket lifetime in seconds.
    , pruningDelay :: Int
    -- ^ Pruning delay in seconds. This is set to 'reaperDelay'.
    , dbMaxSize :: Int
    -- ^ The limit size of session data entries.
    }

-- | ticketLifetime: 2 hours (7200 seconds), pruningDelay: 10 minutes (600 seconds), dbMaxSize: 1000 entries.
defaultConfig :: Config
defaultConfig =
    Config
        { ticketLifetime = 7200
        , pruningDelay = 600
        , dbMaxSize = 1000
        }

----------------------------------------------------------------

toKey :: ByteString -> SessionIDCopy
toKey = SBS.toShort

toValue :: SessionData -> SessionDataCopy
toValue sd =
    SessionDataCopy $
        sd
            { sessionSecret = convert $ sessionSecret sd
            , sessionALPN = convert <$> sessionALPN sd
            }

fromValue :: SessionDataCopy -> SessionData
fromValue (SessionDataCopy sd) =
    sd
        { sessionSecret = convert $ sessionSecret sd
        , sessionALPN = convert <$> sessionALPN sd
        }

----------------------------------------------------------------

type SessionIDCopy = ShortByteString
newtype SessionDataCopy = SessionDataCopy SessionData
    deriving (Show, Eq)

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
    reaper <-
        mkReaper
            defaultReaperSettings
                { reaperEmpty = Q.empty
                , reaperCons = cons maxsiz
                , reaperAction = clean
                , reaperNull = Q.null
                , reaperDelay = pruningDelay conf * 1000000
                , reaperThreadName = "TLS session manager"
                }
    return $
        noSessionManager
            { sessionResume = resume reaper MultipleUse
            , sessionResumeOnlyOnce = resume reaper SingleUse
            , sessionEstablish = \x y -> establish reaper lifetime x y >> return Nothing
            , sessionInvalidate = invalidate reaper
            , sessionUseTicket = False
            }

cons :: Int -> Item -> DB -> DB
cons lim (k, t, v, Add) db
    | lim <= 0 = Q.empty
    | Q.size db == lim = case Q.minView db of
        Nothing -> assert False $ Q.insert k t v Q.empty
        Just (_, _, _, db') -> Q.insert k t v db'
    | otherwise = Q.insert k t v db
cons _ (k, _, _, Del) db = Q.delete k db

clean :: DB -> IO (DB -> DB)
clean olddb = do
    currentTime <- C.sec <$> C.getTime C.Monotonic
    let pruned = snd $ Q.atMostView currentTime olddb
    return $ merge pruned
  where
    ins db (k, p, v) = Q.insert k p v db
    -- There is not 'merge' API.
    -- We hope that newdb is smaller than pruned.
    merge pruned newdb = foldl' ins pruned entries
      where
        entries = Q.toList newdb

----------------------------------------------------------------

establish
    :: Reaper DB Item
    -> Sec
    -> SessionID
    -> SessionData
    -> IO ()
establish reaper lifetime k sd = do
    ref <- newIORef Fresh
    p <- (+ lifetime) . C.sec <$> C.getTime C.Monotonic
    let v = (sd', ref)
    reaperAdd reaper (k', p, v, Add)
  where
    k' = toKey k
    sd' = toValue sd

resume
    :: Reaper DB Item
    -> Use
    -> SessionID
    -> IO (Maybe SessionData)
resume reaper use k = do
    db <- reaperRead reaper
    case Q.lookup k' db of
        Nothing -> return Nothing
        Just (p, v@(sd, ref)) ->
            case use of
                SingleUse -> do
                    available <- atomicModifyIORef' ref check
                    reaperAdd reaper (k', p, v, Del)
                    return $ if available then Just (fromValue sd) else Nothing
                MultipleUse -> return $ Just (fromValue sd)
  where
    check Fresh = (Used, True)
    check Used = (Used, False)
    k' = toKey k

invalidate
    :: Reaper DB Item
    -> SessionID
    -> IO ()
invalidate reaper k = do
    db <- reaperRead reaper
    case Q.lookup k' db of
        Nothing -> return ()
        Just (p, v) -> reaperAdd reaper (k', p, v, Del)
  where
    k' = toKey k
