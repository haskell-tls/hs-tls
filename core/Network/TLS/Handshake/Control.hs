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
  , putRecordWith
  , handshakeCheck
  ) where

import Network.TLS.Cipher
import Network.TLS.Handshake.State
import Network.TLS.Imports
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types

import qualified Control.Exception as E
import qualified Data.ByteString as B
import Data.IORef

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

data ClientControl = GetClientHello                 -- ^ 'SendClientHello'
                   | PutServerHello ServerHello     -- ^ 'SendClientHello', 'RecvServerHello', 'ClientNeedsMore'
                   | PutServerFinished Finished     -- ^ 'SendClientFinished'
                   | PutSessionTicket SessionTicket -- ^ 'RecvSessionTicket'
                   | ExitClient                     -- ^ 'ClientHandshakeDone'

data ServerControl = PutClientHello ClientHello -- ^ 'SendRequestRetry', 'SendServerHello', 'ServerNeedsMore'
                   | GetServerFinished          -- ^ 'SendServerFinished'
                   | PutClientFinished Finished -- ^ 'SendSessionTicket', 'ServerNeedsMore'
                   | ExitServer                 -- ^ 'ServerHandshakeDone'

data ClientStatus =
    ClientNeedsMore
  | SendClientHello ClientHello
  | RecvServerHello
  | SendClientFinished Finished
  | RecvSessionTicket
  | ClientHandshakeDone

instance Show ClientStatus where
    show ClientNeedsMore{}     = "ClientNeedsMore"
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
    ServerNeedsMore
  | SendRequestRetry ServerHello
  | SendServerHello ServerHello
  | SendServerFinished Finished
  | SendSessionTicket SessionTicket
  | ServerHandshakeDone

instance Show ServerStatus where
    show ServerNeedsMore{}     = "ServerNeedsMore"
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

----------------------------------------------------------------

putRecordWith :: (ByteString -> IO ())
              -> IORef (Maybe ByteString)
              -> ByteString
              -> HandshakeType13
              -> a
              -> IO a
              -> IO a
putRecordWith put ref bs1 htyp needsMore body = do
    mbs0 <- readIORef ref
    let bs = case mbs0 of
          Nothing  -> bs1
          Just bs0 -> bs0 `B.append` bs1
    (done,mbs) <- handshakeCheck put htyp bs
    writeIORef ref mbs
    if done then body else return needsMore

handshakeCheck :: (ByteString -> IO ()) -> HandshakeType13 -> ByteString
               -> IO (Bool, Maybe ByteString)
handshakeCheck put htyp bs0 = loop bs0
  where
    loop bs
      | B.length bs < 4 = return (False, Just bs)
    loop bs = case mhtyp0 of
      Nothing    -> E.throwIO $ Error_Packet_Parsing "Unknown Handshake13 type"
      Just htyp0 -> case B.length bs `compare` (len + 4) of
          EQ | htyp == htyp0 -> do
                   put bs
                   return (True, Nothing)
             | otherwise   -> do
                   put bs
                   return (False, Nothing)
          GT | htyp == htyp0 -> do
                   let (record, rest) = B.splitAt (len + 4) bs
                   put record
                   return (True, Just rest)
             | otherwise   -> do
                   let (record, rest) = B.splitAt (len + 4) bs
                   put record
                   loop rest
          LT               -> return (False, Just bs)
      where
        mhtyp0 = valToType (bs `B.index` 0)
        len1 = fromIntegral (bs `B.index` 1)
        len2 = fromIntegral (bs `B.index` 2)
        len3 = fromIntegral (bs `B.index` 3)
        len   = len1 * 65536 + len2 * 256 + len3
