-- |
-- Module      : Network.TLS.Session
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Session
    ( SessionManager(..)
    , nullSessionManager
    ) where

import Network.TLS.Types

-- | A session manager
data SessionManager = SessionManager
    { -- | used on server side to decide whether to resume a client session.
      sessionResume     :: SessionID -> IO (Maybe SessionData)
      -- | used when a session is established.
    , sessionEstablish  :: SessionID -> SessionData -> IO ()
      -- | used when a session is invalidated.
    , sessionInvalidate :: SessionID -> IO ()
    }

nullSessionManager :: SessionManager
nullSessionManager = SessionManager
    { sessionResume     = \_   -> return Nothing
    , sessionEstablish  = \_ _ -> return ()
    , sessionInvalidate = \_   -> return ()
    }
