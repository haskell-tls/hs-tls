-- |
-- Module      : Network.TLS.PostHandshake
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.PostHandshake
    ( requestCertificate
    , requestCertificateServer
    , postHandshakeAuthWith
    , postHandshakeAuthClientWith
    , postHandshakeAuthServerWith
    ) where

import Network.TLS.Context.Internal
import Network.TLS.IO
import Network.TLS.Struct13

import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Client
import Network.TLS.Handshake.Server

import Control.Monad.State.Strict

-- | Post-handshake certificate request with TLS 1.3.  Returns 'True' if the
-- request was possible, i.e. if TLS 1.3 is used and the remote client supports
-- post-handshake authentication.
requestCertificate :: MonadIO m => Context -> m Bool
requestCertificate ctx =
    liftIO $ withWriteLock ctx $
        checkValid ctx >> ctxDoRequestCertificate ctx ctx

-- Handle a post-handshake authentication flight with TLS 1.3.  This is called
-- automatically by 'recvData', in a context where the read lock is already
-- taken.
postHandshakeAuthWith :: MonadIO m => Context -> Handshake13 -> m ()
postHandshakeAuthWith ctx hs =
    liftIO $ withWriteLock ctx $ handleException ctx $ ctxDoPostHandshakeAuthWith ctx ctx hs
