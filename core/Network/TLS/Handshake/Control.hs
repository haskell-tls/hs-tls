-- |
-- Module      : Network.TLS.Handshake.Control
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.Control (
    ClientControl(..)
  , ServerControl(..)
  , ClientStatus(..)
  , ClientStatusI(..)
  , ServerStatus(..)
  , ServerStatusI(..)
  , ClientController
  , ServerController
  , EarlySecretInfo(..)
  , HandshakeSecretInfo(..)
  , ApplicationSecretInfo(..)
  , NegotiatedProtocol
  , HandshakeSync(..)
  ) where

import Network.TLS.Cipher
import Network.TLS.Handshake.State
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
data ApplicationSecretInfo = ApplicationSecretInfo HandshakeMode13 (Maybe NegotiatedProtocol) (TrafficSecrets ApplicationSecret)
                         deriving Show

----------------------------------------------------------------

-- | Interface to execute the next handshake step for a TLS client.
type ClientController = ClientControl -> IO ClientStatus

-- | Interface to execute the next handshake step for a TLS server.
type ServerController = ServerControl -> IO ServerStatus

-- | Tell what step to execute in the client handshake.
data ClientControl
    = EnterClient
      -- ^ Start and run the client handshake until the @Finished@ message is
      -- sent.
      --
      -- Possible responses: 'ClientHandshakeComplete', 'ClientHandshakeFailed'
    | RecvSessionTickets
      -- ^ Continue to listen to incoming messages in order to receive and
      -- process session tickets.  This call can be repeated until external
      -- confirmation is received that server already sent all tickets.
      --
      -- Possible responses: 'ClientRecvSessionTicket', 'ClientHandshakeFailed'
    | ExitClient
      -- ^ Terminate the TLS client, possibly prematurely, and free resources.
      --
      -- Possible response: 'ClientHandshakeDone'

-- | Tell what step to execute in the server handshake.
data ServerControl
    = EnterServer
      -- ^ Start and run the server handshake until the @Finished@ message is
      -- sent.
      --
      -- Possible responses: 'ServerFinishedSent', 'ServerHandshakeFailed'
    | CompleteServer
      -- ^ Continue the handshake in order to receive the client @Finished@
      -- message and complete the handshake.
      --
      -- Possible responses: 'ServerHandshakeComplete', 'ServerHandshakeFailed'
    | ExitServer
      -- ^ Terminate the TLS server, possibly prematurely, and free resources.
      --
      -- Possible response: 'ServerHandshakeDone'

-- | Handshake status of the TLS client.
data ClientStatus
  = ClientHandshakeComplete
    -- ^ The client just sent its @Finished@ message sucessfully, so the
    -- handshake is considered complete.  Still the client should continue to
    -- run in order to receive session tickets, until final confirmation by the
    -- server.
  | ClientRecvSessionTicket
    -- ^ The client has received one session ticket successfully, and can still
    -- run in case the server wants to send more tickets.
  | ClientHandshakeDone
    -- ^ The client exited sucessfully and released all resources.
  | ClientHandshakeFailed TLSError
    -- ^ The client handshake aborted prematurely for the specified reason and
    -- resources have been released.  An alert can be sent to the peer.
  deriving Show

data ClientStatusI =
    SendClientHelloI (Maybe EarlySecretInfo)
  | RecvServerHelloI HandshakeSecretInfo
  | SendClientFinishedI [ExtensionRaw] ApplicationSecretInfo
  | RecvSessionTicketI
  | ClientHandshakeFailedI TLSError

-- | Handshake status of the TLS server.
data ServerStatus
  = ServerFinishedSent
    -- ^ The server just sent its @Finished@ message sucessfully, and now
    -- expects to receive the final client flight.
    --
    -- Application traffic secrets have been installed so the server can already
    -- send application traffic if required (but to an unverified client at this
    -- point).
  | ServerHandshakeComplete
    -- ^ The server just received and verified the client @Finished@ message, so
    -- the handshake is considered complete and confirmed.  Session tickets have
    -- been emitted sucessfully too.
  | ServerHandshakeDone
    -- ^ The server exited sucessfully and released all resources.
  | ServerHandshakeFailed TLSError
    -- ^ The server handshake aborted prematurely for the specified reason and
    -- resources have been released.  An alert can be sent to the peer.
  deriving Show

data ServerStatusI =
    SendServerHelloI [ExtensionRaw] (Maybe EarlySecretInfo) HandshakeSecretInfo
  | SendServerFinishedI ApplicationSecretInfo
  | SendSessionTicketI
  | ServerHandshakeFailedI TLSError

----------------------------------------------------------------

data HandshakeSync = HandshakeSync (ClientStatusI -> IO ())
                                   (ServerStatusI -> IO ())
