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

type NegotiatedProtocol = ByteString

data EarlySecretInfo = EarlySecretInfo Cipher (ClientTrafficSecret EarlySecret)
                       deriving Show

data HandshakeSecretInfo = HandshakeSecretInfo Cipher (TrafficSecrets HandshakeSecret)
                         deriving Show

data ApplicationSecretInfo = ApplicationSecretInfo HandshakeMode13 (Maybe NegotiatedProtocol) (TrafficSecrets ApplicationSecret)
                         deriving Show

----------------------------------------------------------------

type ClientController = ClientControl -> IO ClientStatus
type ServerController = ServerControl -> IO ServerStatus

data ClientControl = EnterClient          -- ^ 'ClientHandshakeComplete', 'ClientHandshakeFailed'
                   | RecvSessionTickets   -- ^ 'ClientRecvSessionTicket', 'ClientHandshakeFailed'
                   | ExitClient           -- ^ 'ClientHandshakeDone'

data ServerControl = EnterServer          -- ^ 'ServerFinishedSent', 'ServerHandshakeFailed'
                   | CompleteServer       -- ^ 'ServerHandshakeComplete', 'ServerHandshakeFailed'
                   | ExitServer           -- ^ 'ServerHandshakeDone'

data ClientStatus =
    ClientHandshakeComplete
  | ClientRecvSessionTicket
  | ClientHandshakeDone
  | ClientHandshakeFailed TLSError
  deriving Show

data ClientStatusI =
    SendClientHelloI (Maybe EarlySecretInfo)
  | RecvServerHelloI HandshakeSecretInfo
  | SendClientFinishedI [ExtensionRaw] ApplicationSecretInfo
  | RecvSessionTicketI
  | ClientHandshakeFailedI TLSError

data ServerStatus =
    ServerFinishedSent
  | ServerHandshakeComplete
  | ServerHandshakeDone
  | ServerHandshakeFailed TLSError
  deriving Show

data ServerStatusI =
    SendServerHelloI [ExtensionRaw] (Maybe EarlySecretInfo) HandshakeSecretInfo
  | SendServerFinishedI ApplicationSecretInfo
  | SendSessionTicketI
  | ServerHandshakeFailedI TLSError

----------------------------------------------------------------

data HandshakeSync = HandshakeSync (ClientStatusI -> IO ())
                                   (ServerStatusI -> IO ())
