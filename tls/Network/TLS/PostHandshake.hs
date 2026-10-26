module Network.TLS.PostHandshake (
    requestCertificate,
    requestCertificateServer,
    requestCertificateAsync,
    requestCertificateAsyncServer,
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
-- if the request was impossible, i.e. the remote client does not support
-- post-handshake authentication or the connection is established in
-- TLS 1.2. Returns 'True' if the client authentication succeeds. An
-- exception is thrown if the authentication fails. Server only.
--
-- This reads the client's response by itself, so it must not be called
-- while another thread is in 'recvData'.
{-# DEPRECATED requestCertificate "Use requestCertificateAsync" #-}
requestCertificate :: Context -> IO Bool
requestCertificate ctx =
    checkValid ctx >> doRequestCertificate_ (ctxRoleParams ctx) ctx

-- | Post-handshake certificate request with TLS 1.3, without waiting for
-- the response.  The response is processed by 'recvData', so another
-- thread or the caller itself must keep calling it.  The returned action
-- gives the result; with 'True' it blocks until the result is known, with
-- 'False' it returns 'PHAPending' meanwhile.  Only one request may be
-- pending.  'getClientCertificateChain' gives the authenticated chain.
-- Server only.
requestCertificateAsync :: Context -> IO (Bool -> IO PHAResult)
requestCertificateAsync ctx =
    checkValid ctx >> doRequestCertificateAsync_ (ctxRoleParams ctx) ctx

-- | Handle a post-handshake authentication flight with TLS 1.3.  This
-- is called automatically by 'recvData', in a context where the read
-- lock is already taken. Client only.
postHandshakeAuthWith :: Context -> Handshake13R -> IO ()
postHandshakeAuthWith ctx hb =
    withWriteLock ctx $
        handleException ctx $
            doPostHandshakeAuthWith_ (ctxRoleParams ctx) ctx hb
