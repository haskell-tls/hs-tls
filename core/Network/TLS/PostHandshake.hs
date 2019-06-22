-- |
-- Module      : Network.TLS.PostHandshake
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.PostHandshake
    ( postHandshakeAuthWith
    , postHandshakeAuthClientWith
    , postHandshakeAuthServerWith
    ) where

import Network.TLS.Context.Internal
import Network.TLS.Struct13

import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Client
import Network.TLS.Handshake.Server

import Control.Monad.State.Strict

-- Handle a post-handshake authentication flight with TLS 1.3.  This is called
-- automatically by 'recvData', in a context where the read lock is already
-- taken.
postHandshakeAuthWith :: MonadIO m => Context -> Handshake13 -> m ()
postHandshakeAuthWith ctx hs =
    liftIO $ withWriteLock ctx $ handleException ctx $ ctxDoPostHandshakeAuthWith ctx ctx hs
