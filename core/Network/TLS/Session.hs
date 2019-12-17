-- |
-- Module      : Network.TLS.Session
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Session
    ( SessionManager(..)
    , noSessionManager
    ) where

import Network.TLS.Types

-- | A session manager
data SessionManager = SessionManager
    { -- | used on server side to decide whether to resume a client session.
      sessionResume         :: SessionID -> IO (Maybe SessionData)
      -- | used on server side to decide whether to resume a client session for TLS 1.3 0RTT. For a given 'SessionID', the implementation must return its 'SessionData' only once and must not return the same 'SessionData' after the call.
    , sessionResumeOnlyOnce :: SessionID -> IO (Maybe SessionData)
      -- | used when a session is established.
    , sessionEstablish      :: SessionID -> SessionData -> IO ()
      -- | used when a session is invalidated.
    , sessionInvalidate     :: SessionID -> IO ()
    }

-- | The session manager to do nothing.
noSessionManager :: SessionManager
noSessionManager = SessionManager
    { sessionResume         = \_   -> return Nothing
    , sessionResumeOnlyOnce = \_   -> return Nothing
    , sessionEstablish      = \_ _ -> return ()
    , sessionInvalidate     = \_   -> return ()
    }
