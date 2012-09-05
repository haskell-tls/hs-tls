-- |
-- Module      : Network.TLS.Session
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
{-# LANGUAGE ExistentialQuantification #-}
module Network.TLS.Session
    ( SessionManager(..)
    , NoSessionManager(..)
    ) where

import Network.TLS.Types

-- | A session manager
class SessionManager a where
    -- | used on server side to decide whether to resume a client session
    sessionResume     :: a -> SessionID -> IO (Maybe SessionData)
    -- | used when a session is established.
    sessionEstablish  :: a -> SessionID -> SessionData -> IO ()
    -- | used when a session is invalidated
    sessionInvalidate :: a -> SessionID -> IO ()

data NoSessionManager = NoSessionManager

instance SessionManager NoSessionManager where
    sessionResume     _ _   = return Nothing
    sessionEstablish  _ _ _ = return ()
    sessionInvalidate _ _   = return ()
