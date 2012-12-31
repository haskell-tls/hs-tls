{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE DeriveDataTypeable, OverloadedStrings, ScopedTypeVariables #-}
-- |
-- Module      : Network.TLS.Core
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Core
        (
        -- * Internal packet sending and receiving
          sendPacket
        , recvPacket

        -- * Initialisation and Termination of context
        , bye
        , handshake
        , HandshakeFailed(..)
        , ConnectionNotEstablished(..)

        -- * Next Protocol Negotiation
        , getNegotiatedProtocol

        -- * High level API
        , Terminated(..)
        , sendData
        , recvData
        , recvData'
        ) where

import Network.TLS.Context
import Network.TLS.Struct
import Network.TLS.State (getSession)
import Network.TLS.IO
import Network.TLS.Session
import Network.TLS.Handshake
import Data.Typeable
import qualified Network.TLS.State as S
import qualified Data.ByteString as B
import Data.ByteString.Char8 ()
import qualified Data.ByteString.Lazy as L
import qualified Control.Exception as E

import Control.Monad.State

-- | Early termination exception with the reason and the TLS error associated
data Terminated = Terminated Bool String TLSError
                deriving (Eq,Show,Typeable)

instance E.Exception Terminated

-- | notify the context that this side wants to close connection.
-- this is important that it is called before closing the handle, otherwise
-- the session might not be resumable (for version < TLS1.2).
--
-- this doesn't actually close the handle
bye :: MonadIO m => Context -> m ()
bye ctx = sendPacket ctx $ Alert [(AlertLevel_Warning, CloseNotify)]

-- | If the Next Protocol Negotiation extension has been used, this will
-- return get the protocol agreed upon.
getNegotiatedProtocol :: MonadIO m => Context -> m (Maybe B.ByteString)
getNegotiatedProtocol ctx = usingState_ ctx S.getNegotiatedProtocol

-- | sendData sends a bunch of data.
-- It will automatically chunk data to acceptable packet size
sendData :: MonadIO m => Context -> L.ByteString -> m ()
sendData ctx dataToSend = checkValid ctx >> mapM_ sendDataChunk (L.toChunks dataToSend)
        where sendDataChunk d
                | B.length d > 16384 = do
                        let (sending, remain) = B.splitAt 16384 d
                        sendPacket ctx $ AppData sending
                        sendDataChunk remain
                | otherwise = sendPacket ctx $ AppData d

-- | recvData get data out of Data packet, and automatically renegotiate if
-- a Handshake ClientHello is received
recvData :: MonadIO m => Context -> m B.ByteString
recvData ctx = checkValid ctx >> recvPacket ctx >>= either onError process
    where onError err@(Error_Protocol (reason,fatal,desc)) =
            terminate err (if fatal then AlertLevel_Fatal else AlertLevel_Warning) desc reason
          onError err =
            terminate err AlertLevel_Fatal InternalError (show err)

          process (Handshake [ch@(ClientHello {})]) =
            -- on server context receiving a client hello == renegotiation
            case roleParams $ ctxParams ctx of
                Server sparams -> handshakeServerWith sparams ctx ch >> recvData ctx
                Client {}      -> let reason = "unexpected client hello in client context" in
                                  terminate (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
          process (Handshake [HelloRequest]) =
            -- on client context, receiving a hello request == renegotiation
            case roleParams $ ctxParams ctx of
                Server {}      -> let reason = "unexpected hello request in server context" in
                                  terminate (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
                Client cparams -> handshakeClient cparams ctx >> recvData ctx

          process (Alert [(AlertLevel_Warning, CloseNotify)]) = setEOF ctx >> return B.empty
          process (Alert [(AlertLevel_Fatal, desc)]) = do
            setEOF ctx
            liftIO $ E.throwIO (Terminated True ("received fatal error: " ++ show desc) (Error_Protocol ("remote side fatal error", True, desc)))

          -- when receiving empty appdata, we just retry to get some data.
          process (AppData "") = recvData ctx
          process (AppData x)  = return x
          process p            = let reason = "unexpected message " ++ show p in
                                 terminate (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason

          terminate :: MonadIO m => TLSError -> AlertLevel -> AlertDescription -> String -> m a
          terminate err level desc reason = do
            session <- usingState_ ctx getSession
            case session of
                Session Nothing    -> return ()
                Session (Just sid) -> withSessionManager (ctxParams ctx) (\s -> liftIO $ sessionInvalidate s sid)
            liftIO $ E.catch (sendPacket ctx $ Alert [(level, desc)]) (\(_ :: E.SomeException) -> return ())
            setEOF ctx
            liftIO $ E.throwIO (Terminated False reason err)


{-# DEPRECATED recvData' "use recvData that returns strict bytestring" #-}
-- | same as recvData but returns a lazy bytestring.
recvData' :: MonadIO m => Context -> m L.ByteString
recvData' ctx = recvData ctx >>= return . L.fromChunks . (:[])
