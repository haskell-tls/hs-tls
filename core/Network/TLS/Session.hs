-- |
-- Module      : Network.TLS.Session
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
module Network.TLS.Session (
    SessionManager (..),
    noSessionManager,
) where

import Network.TLS.Types

-- | A session manager
data SessionManager = SessionManager
    { sessionResume :: SessionIDorTicket -> IO (Maybe SessionData)
    -- ^ Used on TLS 1.2\/1.3 servers to lookup 'SessionData' with 'SessionID' or to decrypt 'Ticket' to get 'SessionData'.
    , sessionResumeOnlyOnce :: SessionIDorTicket -> IO (Maybe SessionData)
    -- ^ Used for 0RTT on TLS 1.3 servers to lookup 'SessionData' with 'SessionID' or to decrypt 'Ticket' to get 'SessionData'.
    , sessionEstablish :: SessionID -> SessionData -> IO (Maybe Ticket)
    -- ^ Used TLS 1.2\/1.3 servers\/clients to store 'SessionData' with 'SessionID' or to encrypt 'SessionData' to get 'Ticket'. In the client side, 'Nothing' should be returned. For clients, only this field should be set with 'noSessionManager'.
    , sessionInvalidate :: SessionID -> IO ()
    -- ^ Used TLS 1.2\/1.3 servers to delete 'SessionData' with 'SessionID' if @sessionUseTicket@ is 'True'.
    , sessionUseTicket :: Bool
    -- ^ Used on TLS 1.2 servers to decide to use 'SessionID' or 'Ticket'. Note that TLS 1.3 servers always use session tickets.
    }

-- | The session manager to do nothing.
noSessionManager :: SessionManager
noSessionManager =
    SessionManager
        { sessionResume = \_ -> return Nothing
        , sessionResumeOnlyOnce = \_ -> return Nothing
        , sessionEstablish = \_ _ -> return Nothing
        , sessionInvalidate = \_ -> return ()
        , -- Don't send NewSessionTicket in TLS 1.2 by default.
          -- Send NewSessionTicket with SessionID in TLS 1.3 by default.
          sessionUseTicket = False
        }
