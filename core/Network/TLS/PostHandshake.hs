-- |
-- Module      : Network.TLS.PostHandshake
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.PostHandshake
    ( requestCertificate
    , postHandshakeAuthWith
    , postHandshakeAuthClientWith
    , postHandshakeAuthServerWith
    ) where

import Network.TLS.Context.Internal
import Network.TLS.Extension
import Network.TLS.IO
import Network.TLS.Parameters
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types

import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Client
import Network.TLS.Handshake.Server

import Control.Exception (bracket)
import Control.Monad.State.Strict

newCertReqContext :: Context -> IO CertReqContext
newCertReqContext ctx = getStateRNG ctx 32

-- | Post-handshake certificate request with TLS 1.3.  Returns 'True' if the
-- request was possible, i.e. if TLS 1.3 is used and the remote client supports
-- post-handshake authentication.
requestCertificate :: MonadIO m => Context -> m Bool
requestCertificate ctx = liftIO $ do
    tls13 <- tls13orLater ctx
    ok <- usingState_ ctx $ do
        supportsPHA <- getClientSupportsPHA
        cc <- isClientContext
        return (cc == ServerRole && tls13 && supportsPHA)
    when ok $ do
        certReqCtx <- newCertReqContext ctx
        let sigAlgs = extensionEncode $ SignatureAlgorithms $ supportedHashSignatures $ ctxSupported ctx
            crexts = [ExtensionRaw extensionID_SignatureAlgorithms sigAlgs]
            certReq = CertRequest13 certReqCtx crexts
        withWriteLock ctx $ do
            checkValid ctx
            bracket (saveHState ctx) (restoreHState ctx) $ \_ -> do
                addCertRequest13 ctx certReq
                sendPacket13 ctx $ Handshake13 [certReq]
    return ok

-- Handle a post-handshake authentication flight with TLS 1.3.  This is called
-- automatically by 'recvData', in a context where the read lock is already
-- taken.
postHandshakeAuthWith :: MonadIO m => Context -> Handshake13 -> m ()
postHandshakeAuthWith ctx hs =
    liftIO $ withWriteLock ctx $ handleException ctx $ ctxDoPostHandshakeAuthWith ctx ctx hs
