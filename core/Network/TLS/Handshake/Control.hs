{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.Control (
    ClientControl(..)
  , ServerControl(..)
  , ClientStatus(..)
  , ClientStatusI(..)
  , ServerStatus(..)
  , ServerStatusI(..)
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

data ClientControl = GetClientHello       -- ^ 'SendClientFinished'
                   | PutSessionTicket     -- ^ 'RecvSessionTicket'
                   | ExitClient           -- ^ 'ClientHandshakeDone'

data ServerControl = PutClientHello       -- ^ 'SendServerFinished'
                   | PutClientFinished    -- ^ 'SendSessionTicket'
                   | ExitServer           -- ^ 'ServerHandshakeDone'

data ClientStatus =
    SendClientFinished
  | RecvSessionTicket
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
    SendServerFinished
  | SendSessionTicket
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
