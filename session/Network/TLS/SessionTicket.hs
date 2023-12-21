{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Network.TLS.SessionTicket (
    newSessionTicketManager,
    Config,
    defaultConfig,
    ticketLifetime,
) where

import Codec.Serialise
import qualified Crypto.Token as CT
import qualified Data.ByteString.Lazy as L
import Network.TLS
import Network.TLS.Internal

data Config = Config
    { ticketLifetime :: Int
    -- ^ Ticket lifetime in seconds.
    }

-- | Lifetime: 1 day
defaultConfig :: Config
defaultConfig =
    Config
        { ticketLifetime = 86400
        }

newSessionTicketManager :: Config -> IO SessionManager
newSessionTicketManager Config{..} =
    sessionTicketManager <$> CT.spawnTokenManager conf
  where
    intvl = 30 * 60 -- seconds
    conf = CT.defaultConfig{CT.interval = intvl, CT.tokenLifetime = ticketLifetime}

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
