module Network.TLS.Handshake.Control (
    ClientState (..),
    ServerState (..),
    EarlySecretInfo (..),
    HandshakeSecretInfo (..),
    ApplicationSecretInfo (..),
    NegotiatedProtocol,
) where

import Crypto.Debug (DebugShow (..))
import Network.TLS.Cipher
import Network.TLS.Imports
import Network.TLS.Struct
import Network.TLS.Types

----------------------------------------------------------------

-- | ID of the application-level protocol negotiated between client and server.
-- See values listed in the <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids IANA registry>.
type NegotiatedProtocol = ByteString

-- | Handshake information generated for traffic at 0-RTT level.
--
-- 'Show' renders the cipher and @\<secret\>@ for the key material; a trace
-- of what 'Network.TLS.QUIC.quicInstallKeys' is handed does not write the
-- traffic secrets to a log.  'Crypto.Debug.debugShow' renders them.
data EarlySecretInfo = EarlySecretInfo Cipher (ClientTrafficSecret EarlySecret)
    deriving (Show)

instance DebugShow EarlySecretInfo where
    debugShow (EarlySecretInfo c s) =
        "EarlySecretInfo " ++ show c ++ " " ++ debugShow s

-- | Handshake information generated for traffic at handshake level.
--
-- The secrets are not shown; see 'EarlySecretInfo'.
data HandshakeSecretInfo
    = HandshakeSecretInfo Cipher (TrafficSecrets HandshakeSecret)
    deriving (Show)

instance DebugShow HandshakeSecretInfo where
    debugShow (HandshakeSecretInfo c ts) =
        "HandshakeSecretInfo " ++ show c ++ " " ++ debugShowPair ts

-- | Handshake information generated for traffic at application level.
--
-- The secrets are not shown; see 'EarlySecretInfo'.
newtype ApplicationSecretInfo = ApplicationSecretInfo (TrafficSecrets ApplicationSecret)
    deriving (Show)

instance DebugShow ApplicationSecretInfo where
    debugShow (ApplicationSecretInfo ts) =
        "ApplicationSecretInfo " ++ debugShowPair ts

debugShowPair :: TrafficSecrets a -> String
debugShowPair (c, s) = "(" ++ debugShow c ++ "," ++ debugShow s ++ ")"

----------------------------------------------------------------

data ClientState
    = SendClientHello (Maybe EarlySecretInfo)
    | RecvServerHello HandshakeSecretInfo
    | SendClientFinished [ExtensionRaw] ApplicationSecretInfo

data ServerState
    = SendServerHello [ExtensionRaw] (Maybe EarlySecretInfo) HandshakeSecretInfo
    | SendServerFinished ApplicationSecretInfo
