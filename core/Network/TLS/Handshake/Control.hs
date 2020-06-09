-- |
-- Module      : Network.TLS.Handshake.Control
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.Control (
    ClientState(..)
  , ServerState(..)
  , EarlySecretInfo(..)
  , HandshakeSecretInfo(..)
  , ApplicationSecretInfo(..)
  , NegotiatedProtocol
  ) where

import Network.TLS.Cipher
import Network.TLS.Imports
import Network.TLS.Struct
import Network.TLS.Types

----------------------------------------------------------------

-- | ID of the application-level protocol negotiated between client and server.
-- See values listed in the <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids IANA registry>.
type NegotiatedProtocol = ByteString

-- | Handshake information generated for traffic at 0-RTT level.
data EarlySecretInfo = EarlySecretInfo Cipher (ClientTrafficSecret EarlySecret)
                       deriving Show

-- | Handshake information generated for traffic at handshake level.
data HandshakeSecretInfo = HandshakeSecretInfo Cipher (TrafficSecrets HandshakeSecret)
                         deriving Show

-- | Handshake information generated for traffic at application level.
newtype ApplicationSecretInfo = ApplicationSecretInfo (TrafficSecrets ApplicationSecret)
                         deriving Show

----------------------------------------------------------------

data ClientState =
    SendClientHello (Maybe EarlySecretInfo)
  | RecvServerHello HandshakeSecretInfo
  | SendClientFinished [ExtensionRaw] ApplicationSecretInfo

data ServerState =
    SendServerHello [ExtensionRaw] (Maybe EarlySecretInfo) HandshakeSecretInfo
  | SendServerFinished ApplicationSecretInfo
