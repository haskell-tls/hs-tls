module Network.TLS.Handshake (
    handshake_,
    handshakeWith,
    handshakeClientWith,
    handshakeServerWith,
    handshakeClient,
    handshakeServer,
) where

import Network.TLS.Context.Internal
import Network.TLS.Handshake.Client
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Server
import Network.TLS.Struct

import Control.Monad.State.Strict

handshake_ :: MonadIO m => Context -> m ()
handshake_ ctx =
    liftIO $
        withRWLock ctx $
            handleException ctx (doHandshake_ (ctxRoleParams ctx) ctx)

-- Handshake when requested by the remote end
-- This is called automatically by 'recvData', in a context where the read lock
-- is already taken.  So contrary to 'handshake' above, here we only need to
-- call withWriteLock.
handshakeWith :: MonadIO m => Context -> Handshake -> m ()
handshakeWith ctx hs =
    liftIO $
        withWriteLock ctx $
            handleException ctx $
                doHandshakeWith_ (ctxRoleParams ctx) ctx hs
