{-# LANGUAGE RecordWildCards #-}

-- |
-- process handshake message received
module Network.TLS.Handshake.Process (
    processHandshake,
    processHandshake13,
    startHandshake,
) where

import Control.Concurrent.MVar

import Network.TLS.Context.Internal
import Network.TLS.Handshake.Random
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.Imports
import Network.TLS.Sending
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types (Role (..))

processHandshake :: Context -> Handshake -> IO ()
processHandshake ctx hs = do
    role <- usingState_ ctx getRole
    when (isHRR hs) $ usingHState ctx wrapAsMessageHash13
    case hs of
        ClientKeyXchg _
            | role == ServerRole -> return ()
        _ -> void $ updateHandshake ctx False hs
  where
    isHRR (ServerHello TLS12 srand _ _ _ _) = isHelloRetryRequest srand
    isHRR _ = False

processHandshake13 :: Context -> Handshake13 -> IO ()
processHandshake13 ctx = void . updateHandshake13 ctx

-- initialize a new Handshake context (initial handshake or renegotiations)
startHandshake :: Context -> Version -> ClientRandom -> IO ()
startHandshake ctx ver crand =
    let hs = Just $ newEmptyHandshake ver crand
     in void $ swapMVar (ctxHandshake ctx) hs
