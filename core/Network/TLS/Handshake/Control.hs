{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.Control (
    ClientControl(..)
  , ServerControl(..)
  , ClientStatus(..)
  , ClientStatusI(..)
  , ServerStatus(..)
  , ServerStatusI(..)
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
import Network.TLS.Imports
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types

import qualified Data.ByteString as B
import Data.IORef

----------------------------------------------------------------

type NegotiatedProtocol = ByteString
type ClientHello = ByteString
type ServerHello = ByteString
type Finished = ByteString
type SessionTicket = ByteString

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
  | SendClientHello ClientHello (Maybe (ClientTrafficSecret EarlySecret))
  | RecvServerHello Cipher (TrafficSecrets HandshakeSecret)
  | SendClientFinished Finished [ExtensionRaw] (Maybe NegotiatedProtocol) (TrafficSecrets ApplicationSecret)
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
    SendClientHelloI (Maybe (ClientTrafficSecret EarlySecret))
  | RecvServerHelloI Cipher (TrafficSecrets HandshakeSecret)
  | SendClientFinishedI [ExtensionRaw] (Maybe NegotiatedProtocol) (TrafficSecrets ApplicationSecret)
  | RecvSessionTicketI

data ServerStatus =
    ServerNeedsMore
  | SendRequestRetry ServerHello
  | SendServerHello ServerHello
                    [ExtensionRaw]
                    Cipher
                    (Maybe (ClientTrafficSecret EarlySecret))
                    (TrafficSecrets HandshakeSecret)
  | SendServerFinished Finished
                       (Maybe NegotiatedProtocol)
                       (TrafficSecrets ApplicationSecret)
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
  | SendServerHelloI [ExtensionRaw]
                     Cipher
                     (Maybe (ClientTrafficSecret EarlySecret))
                     (TrafficSecrets HandshakeSecret)
  | SendServerFinishedI (Maybe NegotiatedProtocol)
                        (TrafficSecrets ApplicationSecret)
  | SendSessionTicketI

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
    loop bs = case B.length bs `compare` (len + 4) of
          EQ | typ == styp -> do
                   put bs
                   return (True, Nothing)
             | otherwise   -> do
                   put bs
                   return (False, Nothing)
          GT | typ == styp -> do
                   let (record, rest) = B.splitAt (len + 4) bs
                   put record
                   return (True, Just rest)
             | otherwise   -> do
                   let (record, rest) = B.splitAt (len + 4) bs
                   put record
                   loop rest
          LT               -> return (False, Just bs)
      where
        styp = valOfType htyp
        typ  = bs `B.index` 0
        len1 = fromIntegral (bs `B.index` 1)
        len2 = fromIntegral (bs `B.index` 2)
        len3 = fromIntegral (bs `B.index` 3)
        len   = len1 * 65536 + len2 * 256 + len3
