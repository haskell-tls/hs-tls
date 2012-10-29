{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE DeriveDataTypeable, OverloadedStrings #-}
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
        , sendData
        , recvData
        , recvData'
        ) where

import Network.TLS.Context
import Network.TLS.Struct
import Network.TLS.IO
import Network.TLS.Handshake
import qualified Network.TLS.State as S
import qualified Data.ByteString as B
import Data.ByteString.Char8 ()
import qualified Data.ByteString.Lazy as L

import Control.Monad.State

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
recvData ctx = do
        checkValid ctx
        pkt <- recvPacket ctx
        case pkt of
                -- on server context receiving a client hello == renegotiation
                Right (Handshake [ch@(ClientHello {})]) ->
                        case roleParams $ ctxParams ctx of
                            Server sparams -> handshakeServerWith sparams ctx ch >> recvData ctx
                            Client {}      -> error "assert, unexpected client hello in client context"
                -- on client context, receiving a hello request == renegotiation
                Right (Handshake [HelloRequest]) ->
                        case roleParams $ ctxParams ctx of
                            Server {}      -> error "assert, unexpected hello request in server context"
                            Client cparams -> handshakeClient cparams ctx >> recvData ctx
                Right (Alert [(AlertLevel_Fatal, _)]) -> do
                        setEOF ctx
                        return B.empty
                Right (Alert [(AlertLevel_Warning, CloseNotify)]) -> do
                        setEOF ctx
                        return B.empty
                Right (AppData "") -> recvData ctx
                Right (AppData x)  -> return x
                Right p            -> error ("error unexpected packet: " ++ show p)
                Left err           -> error ("error received: " ++ show err)

{-# DEPRECATED recvData' "use recvData that returns strict bytestring" #-}
-- | same as recvData but returns a lazy bytestring.
recvData' :: MonadIO m => Context -> m L.ByteString
recvData' ctx = recvData ctx >>= return . L.fromChunks . (:[])
