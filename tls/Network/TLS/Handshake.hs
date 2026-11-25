module Network.TLS.Handshake (
    handshake_,
    handshakeLocked,
    renegotiate,
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
handshake_ ctx = liftIO $ withRWLock ctx $ handshakeLocked ctx

-- | 'handshake_' with the read and write locks taken already.
handshakeLocked :: Context -> IO ()
handshakeLocked ctx = handleException ctx (doHandshake_ (ctxRoleParams ctx) ctx)

-- Handshake when requested by the remote end
-- This is called automatically by 'recvData', in a context where the read lock
-- is already taken.  So contrary to 'handshake' above, here we only need to
-- call withWriteLock.
renegotiate :: MonadIO m => Context -> HandshakeR -> m ()
renegotiate ctx hsr =
    liftIO $
        withWriteLock ctx $
            handleException ctx $
                doHandshakeWith_ (ctxRoleParams ctx) ctx hsr
