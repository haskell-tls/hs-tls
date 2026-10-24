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
import qualified Network.TLS.Internal as I
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
type Sessions = OrdPSQ SessionIDCopy Sec Value

-- | The sessions, and the keys deleted since the reaper last took them away
-- to prune.  While it prunes, the workload left in their place is empty, so
-- a deletion there is kept to be applied to the pruned sessions too.
data DB = DB Sessions [SessionIDCopy]

data Item = Add SessionIDCopy Sec Value | Del SessionIDCopy

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
                { reaperEmpty = DB Q.empty []
                , reaperCons = cons maxsiz
                , reaperAction = clean maxsiz
                , reaperNull = \(DB q _) -> Q.null q
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
cons lim (Add k t v) (DB q ds)
    | lim <= 0 = DB Q.empty ds
    -- Replacing a session makes no room for it.
    | Q.size q == lim && not (Q.member k q) = case Q.minView q of
        Nothing -> assert False $ DB (Q.insert k t v Q.empty) ds
        Just (_, _, _, q') -> DB (Q.insert k t v q') ds
    | otherwise = DB (Q.insert k t v q) ds
-- At most as many keys as there can be sessions are kept.
cons lim (Del k) (DB q ds) = DB (Q.delete k q) (take lim (k : ds))

clean :: Int -> DB -> IO (DB -> DB)
clean lim (DB oldq _) = do
    currentTime <- C.sec <$> C.getTime C.Monotonic
    let pruned = snd $ Q.atMostView currentTime oldq
    return $ merge pruned
  where
    ins q (k, p, v) = Q.insert k p v q
    -- There is not 'merge' API.
    -- We hope that the new sessions are fewer than the pruned ones.
    merge pruned (DB newq ds) = DB (limit $ foldl' ins (foldr Q.delete pruned ds) entries) []
      where
        entries = Q.toList newq
    -- The size was checked against the new sessions alone.
    limit q
        | lim <= 0 = Q.empty
        | Q.size q > lim = maybe q (\(_, _, _, q') -> limit q') $ Q.minView q
        | otherwise = q

----------------------------------------------------------------

establish
    :: Reaper DB Item
    -> Sec
    -> SessionID
    -> SessionData
    -> IO ()
establish reaper lifetime k sd = do
    ref <- newIORef Fresh
    p <- (+ lifetime') . C.sec <$> C.getTime C.Monotonic
    let v = (sd', ref)
    reaperAdd reaper (Add k' p v)
  where
    k' = toKey k
    sd' = toValue sd
    -- A TLS 1.3 ticket is not kept past the lifetime the server gave it.
    lifetime' = case sessionTicketInfo sd of
        Just tinfo -> min lifetime (fromIntegral (I.lifetime tinfo))
        Nothing -> lifetime

resume
    :: Reaper DB Item
    -> Use
    -> SessionID
    -> IO (Maybe SessionData)
resume reaper use k = do
    DB q _ <- reaperRead reaper
    now <- C.sec <$> C.getTime C.Monotonic
    case Q.lookup k' q of
        -- An expired session stays until the next pruning; it is not used.
        Just (p, (sd, ref))
            | p > now -> case use of
                SingleUse -> do
                    available <- atomicModifyIORef' ref check
                    reaperAdd reaper (Del k')
                    return $ if available then Just (fromValue sd) else Nothing
                MultipleUse -> return $ Just (fromValue sd)
        _ -> return Nothing
  where
    check Fresh = (Used, True)
    check Used = (Used, False)
    k' = toKey k

invalidate
    :: Reaper DB Item
    -> SessionID
    -> IO ()
-- Not looked up first: while the reaper prunes, the session is not seen.
invalidate reaper k = reaperAdd reaper (Del (toKey k))
