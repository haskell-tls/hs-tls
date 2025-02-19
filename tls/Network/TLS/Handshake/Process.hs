-- |
-- process handshake message received
module Network.TLS.Handshake.Process (
    processHandshake12,
    processHandshake13,
) where

import Network.TLS.Context.Internal
import Network.TLS.Handshake.State13
import Network.TLS.IO.Encode
import Network.TLS.Imports
import Network.TLS.Struct
import Network.TLS.Struct13

processHandshake12 :: Context -> Handshake -> IO ()
processHandshake12 ctx hs = do
    when (isHRR hs) $ usingHState ctx wrapAsMessageHash13
    void $ updateHandshake12 ctx hs
  where
    isHRR (ServerHello TLS12 srand _ _ _ _) = isHelloRetryRequest srand
    isHRR _ = False

processHandshake13 :: Context -> Handshake13 -> IO ()
processHandshake13 ctx = void . updateHandshake13 ctx
