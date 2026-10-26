{-# LANGUAGE RecordWildCards #-}

-- | A manager for TLS 1.2/1.3 session ticket.
--
--   For TLS 1.3 0-RTT, a ticket is accepted at most once while a replay
--   of its ClientHello could still be fresh.  This covers one process
--   only: servers sharing the secret keys across processes can still
--   accept a replay in another process.
--
--   A dedicated thread is running repeatedly to replece
--   secret keys. So, energy saving is not achieved.
module Network.TLS.SessionTicket (
    newSessionTicketManager,
    newSessionTicketManager',
    Config,
    defaultConfig,
    ticketLifetime,
    secretKeyInterval,
) where

import Codec.Serialise
import qualified Crypto.Token as CT
import qualified Data.ByteString.Lazy as L
import Data.IORef
import Data.Int (Int64)
import qualified Data.OrdPSQ as Q
import Network.TLS
import Network.TLS.Internal
import System.Clock

-- | Configuration for session tickets.
data Config = Config
    { ticketLifetime :: Int
    -- ^ Ticket lifetime in seconds.  It should match the lifetime the
    -- server announces, 'serverTicketLifetime'.  As the secret keys are
    -- replaced every 'secretKeyInterval', a ticket is accepted for up to
    -- one interval less.
    , secretKeyInterval :: Int
    -- ^ The interval to replace the secret key in seconds.
    }

-- | ticketLifetime: 2 hours (7200 seconds), secretKeyInterval: 30 minutes (1800 seconds)
defaultConfig :: Config
defaultConfig =
    Config
        { ticketLifetime = 7200 -- 2 hours
        , secretKeyInterval = 1800 -- 30 minutes
        }

-- | Creating a session ticket manager.
newSessionTicketManager :: Config -> IO SessionManager
newSessionTicketManager Config{..} =
    sessionTicketManager <$> CT.spawnTokenManager conf <*> newIORef Q.empty
  where
    conf =
        CT.defaultConfig
            { CT.interval = secretKeyInterval
            , CT.tokenLifetime = ticketLifetime
            , CT.threadName = "TLS ticket manager"
            }

newSessionTicketManager' :: Config -> IO (SessionManager, IO ())
newSessionTicketManager' Config{..} = do
    tokenmgr <- CT.spawnTokenManager conf
    used <- newIORef Q.empty
    return (sessionTicketManager tokenmgr used, CT.killTokenManager tokenmgr)
  where
    conf =
        CT.defaultConfig
            { CT.interval = secretKeyInterval
            , CT.tokenLifetime = ticketLifetime
            , CT.threadName = "TLS ticket manager"
            }

-- | Tickets used for 0-RTT, with when they may be forgotten in
-- milliseconds of the monotonic clock.
type Used = IORef (Q.OrdPSQ Ticket Int64 ())

sessionTicketManager :: CT.TokenManager -> Used -> SessionManager
sessionTicketManager ctmgr used =
    noSessionManager
        { sessionResume = resume ctmgr
        , sessionResumeOnlyOnce = resumeOnlyOnce ctmgr used
        , sessionEstablish = establish ctmgr
        , sessionInvalidate = \_ -> return ()
        , sessionUseTicket = True
        }

establish :: CT.TokenManager -> SessionID -> SessionData -> IO (Maybe Ticket)
establish ctmgr _ sd = Just <$> CT.encryptToken ctmgr b
  where
    b = L.toStrict $ serialise sd

resume :: CT.TokenManager -> Ticket -> IO (Maybe SessionData)
resume ctmgr ticket
    | isTicket ticket = do
        msdb <- CT.decryptToken ctmgr ticket
        case msdb of
            Nothing -> return Nothing
            Just sdb -> case deserialiseOrFail $ L.fromStrict sdb of
                Left _ -> return Nothing
                Right sd -> return $ Just sd
    | otherwise = return Nothing

-- A replay has the same age, so the same expected arrival time E, which is
-- within the tolerance of the first use.  The server accepts it only within
-- the tolerance of E, so the ticket is remembered for twice the tolerance.
resumeOnlyOnce :: CT.TokenManager -> Used -> Ticket -> IO (Maybe SessionData)
resumeOnlyOnce ctmgr used ticket = do
    msd <- resume ctmgr ticket
    case msd of
        Nothing -> return Nothing
        Just sd -> do
            now <- milliseconds
            let rtt = maybe 0 fromIntegral $ sessionTicketInfo sd >>= estimatedRTT
                -- 'max 2000 rtt' as in the server, and a second of margin
                forget = now + 2 * max 2000 rtt + 1000
            first <- atomicModifyIORef' used $ \q ->
                let q' = snd $ Q.atMostView now q
                 in case Q.lookup ticket q' of
                        Just _ -> (q', False)
                        Nothing -> (Q.insert ticket forget () q', True)
            return $ if first then Just sd else Nothing

milliseconds :: IO Int64
milliseconds = do
    TimeSpec s ns <- getTime Monotonic
    return $ s * 1000 + ns `div` 1000000
