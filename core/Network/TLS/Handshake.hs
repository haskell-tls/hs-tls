-- |
-- Module      : Network.TLS.Handshake
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake
    ( handshake
    , handshakeWith
    , handshakeClientWith
    , handshakeServerWith
    , handshakeClient
    , handshakeServer
    ) where

import Network.TLS.Context.Internal
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.IO
import Network.TLS.Util (catchException)
import Network.TLS.Imports

import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Client
import Network.TLS.Handshake.Server

import Control.Monad.State.Strict
import Control.Exception (IOException, handle, fromException)

-- | Handshake for a new TLS connection
-- This is to be called at the beginning of a connection, and during renegotiation
handshake :: MonadIO m => Context -> m ()
handshake ctx =
    liftIO $ withRWLock ctx $ handleException ctx (ctxDoHandshake ctx ctx)

-- Handshake when requested by the remote end
-- This is called automatically by 'recvData', in a context where the read lock
-- is already taken.  So contrary to 'handshake' above, here we only need to
-- call withWriteLock.
handshakeWith :: MonadIO m => Context -> Handshake -> m ()
handshakeWith ctx hs =
    liftIO $ withWriteLock ctx $ handleException ctx $ ctxDoHandshakeWith ctx ctx hs

handleException :: Context -> IO () -> IO ()
handleException ctx f = catchException f $ \exception -> do
    let tlserror = fromMaybe (Error_Misc $ show exception) $ fromException exception
    setEstablished ctx NotEstablished
    handle ignoreIOErr $ do
        tls13 <- tls13orLater ctx
        if tls13 then
            sendPacket13 ctx $ Alert13 $ errorToAlert tlserror
          else
            sendPacket ctx $ Alert $ errorToAlert tlserror
    handshakeFailed tlserror
  where
    ignoreIOErr :: IOException -> IO ()
    ignoreIOErr _ = return ()
