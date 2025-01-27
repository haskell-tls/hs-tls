module Network.TLS.PostHandshake (
    requestCertificate,
    requestCertificateServer,
    postHandshakeAuthWith,
    postHandshakeAuthClientWith,
) where

import Network.TLS.Context.Internal
import Network.TLS.IO
import Network.TLS.Struct13

import Network.TLS.Handshake.Client
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Server

-- Server only

-- | Post-handshake certificate request with TLS 1.3.  Returns 'True' if the
-- request was possible, i.e. if TLS 1.3 is used and the remote client supports
-- post-handshake authentication.
requestCertificate :: Context -> IO Bool
requestCertificate ctx =
    checkValid ctx >> doRequestCertificate_ (ctxRoleParams ctx) ctx

-- Client only

-- Handle a post-handshake authentication flight with TLS 1.3.  This is called
-- automatically by 'recvData', in a context where the read lock is already
-- taken.
postHandshakeAuthWith :: Context -> Handshake13 -> IO ()
postHandshakeAuthWith ctx hs =
    withWriteLock ctx $
        handleException ctx $
            doPostHandshakeAuthWith_ (ctxRoleParams ctx) ctx hs
