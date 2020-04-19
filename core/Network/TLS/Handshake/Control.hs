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
  , ClientHello
  , ServerHello
  , Finished
  , SessionTicket
  , HandshakeSync(..)
  ) where

import Network.TLS.Cipher
import Network.TLS.Handshake.State
import Network.TLS.Imports
import Network.TLS.Struct
import Network.TLS.Types

----------------------------------------------------------------

type NegotiatedProtocol = ByteString
type ClientHello = ByteString
type ServerHello = ByteString
type Finished = ByteString
type SessionTicket = ByteString

----------------------------------------------------------------

data EarlySecretInfo = EarlySecretInfo Cipher (ClientTrafficSecret EarlySecret)
                       deriving (Eq, Show)

data HandshakeSecretInfo = HandshakeSecretInfo Cipher (TrafficSecrets HandshakeSecret)
                         deriving (Eq, Show)

data ApplicationSecretInfo = ApplicationSecretInfo HandshakeMode13 (Maybe NegotiatedProtocol) (TrafficSecrets ApplicationSecret)
                         deriving (Eq, Show)

----------------------------------------------------------------

data ClientControl = GetClientHello       -- ^ 'SendClientHello'
                   | PutServerHello       -- ^ 'SendClientHello', 'RecvServerHello'
                   | PutServerFinished    -- ^ 'SendClientFinished'
                   | PutSessionTicket     -- ^ 'RecvSessionTicket'
                   | ExitClient           -- ^ 'ClientHandshakeDone'

data ServerControl = PutClientHello       -- ^ 'SendRequestRetry', 'SendServerHello'
                   | GetServerFinished    -- ^ 'SendServerFinished'
                   | PutClientFinished    -- ^ 'SendSessionTicket'
                   | ExitServer           -- ^ 'ServerHandshakeDone'

data ClientStatus =
    SendClientHello ClientHello
  | RecvServerHello
  | SendClientFinished Finished
  | RecvSessionTicket
  | ClientHandshakeDone

instance Show ClientStatus where
    show SendClientHello{}     = "SendClientHello"
    show RecvServerHello{}     = "RecvServerHello"
    show SendClientFinished{}  = "SendClientFinished"
    show RecvSessionTicket{}   = "RecvSessionTicket"
    show ClientHandshakeDone{} = "ClientHandshakeDone"

data ClientStatusI =
    SendClientHelloI (Maybe EarlySecretInfo)
  | RecvServerHelloI HandshakeSecretInfo
  | SendClientFinishedI [ExtensionRaw] ApplicationSecretInfo
  | RecvSessionTicketI
  | ClientHandshakeFailedI TLSError

data ServerStatus =
    SendRequestRetry ServerHello
  | SendServerHello ServerHello
  | SendServerFinished Finished
  | SendSessionTicket SessionTicket
  | ServerHandshakeDone

instance Show ServerStatus where
    show SendRequestRetry{}    = "SendRequestRetry"
    show SendServerHello{}     = "SendServerHello"
    show SendServerFinished{}  = "SendServerFinished"
    show SendSessionTicket{}   = "SendSessionTicket"
    show ServerHandshakeDone{} = "ServerHandshakeDone"

data ServerStatusI =
    SendRequestRetryI
  | SendServerHelloI [ExtensionRaw] (Maybe EarlySecretInfo) HandshakeSecretInfo
  | SendServerFinishedI ApplicationSecretInfo
  | SendSessionTicketI
  | ServerHandshakeFailedI TLSError

----------------------------------------------------------------

data HandshakeSync = HandshakeSync (ClientStatusI -> IO ())
                                   (ServerStatusI -> IO ())
