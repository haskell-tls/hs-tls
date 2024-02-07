{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -Wno-orphans #-}

-- | A manager for TLS 1.2/1.3 session ticket.
--
--   Tracking client hello is not implemented yet.
--   So, if this is used for TLS 1.3 0-RTT,
--   replay attack is possible.
--   If your application data in 0-RTT changes the status of server side,
--   use 'Network.TLS.SessionManager' instead.
--
--   A dedicated thread is running repeatedly to replece
--   secret keys. So, energy saving is not achieved.
module Network.TLS.SessionTicket (
    newSessionTicketManager,
    Config,
    defaultConfig,
    ticketLifetime,
    secretKeyInterval,
) where

import Codec.Serialise
import qualified Crypto.Token as CT
import qualified Data.ByteString.Lazy as L
import Network.TLS
import Network.TLS.Internal

-- | Configuration for session tickets.
data Config = Config
    { ticketLifetime :: Int
    -- ^ Ticket lifetime in seconds.
    , secretKeyInterval :: Int
    }

-- | ticketLifetime: 2 hours (7200 seconds), secretKeyInterval: 30 minutes (1800 seconds)
defaultConfig :: Config
defaultConfig =
    Config
        { ticketLifetime = 7200 -- 2 hours
        , secretKeyInterval = 1800 -- 30 minites
        }

-- | Creating a session ticket manager.
newSessionTicketManager :: Config -> IO SessionManager
newSessionTicketManager Config{..} =
    sessionTicketManager <$> CT.spawnTokenManager conf
  where
    conf =
        CT.defaultConfig
            { CT.interval = secretKeyInterval
            , CT.tokenLifetime = ticketLifetime
            }

sessionTicketManager :: CT.TokenManager -> SessionManager
sessionTicketManager ctmgr =
    SessionManager
        { sessionResume = resume ctmgr
        , sessionResumeOnlyOnce = resume ctmgr
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

instance Serialise Group
instance Serialise Version
instance Serialise TLS13TicketInfo
instance Serialise SessionFlag
instance Serialise SessionData
