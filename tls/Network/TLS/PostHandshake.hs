module Network.TLS.PostHandshake (
    requestCertificate,
    requestCertificateServer,
    postHandshakeAuthWith,
    postHandshakeAuthClientWith,
) where

import Network.TLS.Context.Internal
import Network.TLS.Handshake.Client
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Server
import Network.TLS.IO
import Network.TLS.Struct13

----------------------------------------------------------------

-- | Post-handshake certificate request with TLS 1.3.  Returns 'False'
-- if the request was impossible, i.e. the remote client supports
-- post-handshake authentication or the connection is established in
-- TLS 1.2. Returns 'True' if the client authentication succeeds. An
-- exception is thrown if the authentication fails. Server only.
requestCertificate :: Context -> IO Bool
requestCertificate ctx =
    checkValid ctx >> doRequestCertificate_ (ctxRoleParams ctx) ctx

-- | Handle a post-handshake authentication flight with TLS 1.3.  This
-- is called automatically by 'recvData', in a context where the read
-- lock is already taken. Client only.
postHandshakeAuthWith :: Context -> Handshake13 -> IO ()
postHandshakeAuthWith ctx hs =
    withWriteLock ctx $
        handleException ctx $
            doPostHandshakeAuthWith_ (ctxRoleParams ctx) ctx hs
