{-# LANGUAGE CPP #-}
{-# LANGUAGE RankNTypes #-}

-- | A Backend represents a unified way to do IO on different
-- types without burdening our calling API with multiple
-- ways to initialize a new context.
--
-- Typically, a backend provides:
--
-- * a way to read data
-- * a way to write data
-- * a way to close the stream
-- * a way to flush the stream
module Network.TLS.Backend (
    HasBackend (..),
    Backend (..),
    RecvWith (..),
) where

import Control.Concurrent.STM (STM)
import qualified Data.ByteString as B
import qualified Network.Socket as Network
import qualified Network.Socket.ByteString as Network
import System.IO (BufferMode (..), Handle, hClose, hFlush, hSetBuffering)

import Network.TLS.Imports

-- | Connection IO backend
data Backend = Backend
    { backendFlush :: IO ()
    -- ^ Flush the connection sending buffer, if any.
    , backendClose :: IO ()
    -- ^ Close the connection.
    , backendSend :: ByteString -> IO ()
    -- ^ Send a bytestring through the connection.
    , backendRecv :: Int -> IO ByteString
    -- ^ Receive the specified number of bytes from the connection.
    -- Fewer bytes are returned only at the end of the stream.
    --
    -- An 'Control.Exception.IOException' means a broken connection: the
    -- context is marked EOF and 'Network.TLS.bye' sends nothing.  Other
    -- exceptions, including asynchronous ones, pass through as they are,
    -- and 'Network.TLS.bye' can still send close_notify.  'Network.TLS.recvData'
    -- may be called again only if the exception was thrown before any byte
    -- of a record was taken.  Thrown inside the body of a record, it is
    -- thrown again by later receives (an asynchronous one as a TLS error).
    }

-- | Types which a 'Network.TLS.Context' can be created on.
class HasBackend a where
    -- | Prepare the connection before use.
    initializeBackend :: a -> IO ()

    -- | The IO functions of the connection.
    getBackend :: a -> Backend

    -- | A receive which can give up.  With it, 'Network.TLS.bye' waits for the
    --   peer's last handshake messages without interrupting a receive.
    --
    -- @since 2.6.0
    getBackendRecvWith :: a -> Maybe RecvWith
    getBackendRecvWith _ = Nothing

-- | A receive of the specified number of bytes which gives up once the
--   'STM' action succeeds, answering what it gave as 'Left'.  Bytes
--   already received by then are answered instead.
--
-- @since 2.6.0
newtype RecvWith = RecvWith (forall g. Int -> STM g -> IO (Either g ByteString))

instance HasBackend Backend where
    initializeBackend _ = return ()
    getBackend = id

safeRecv :: Network.Socket -> Int -> IO ByteString
safeRecv = Network.recv

instance HasBackend Network.Socket where
    initializeBackend _ = return ()
    getBackend sock =
        Backend
            { backendFlush = return ()
            , backendClose = Network.close sock
            , backendSend = Network.sendAll sock
            , backendRecv = recvAll
            }
      where
        recvAll n = B.concat <$> loop n
          where
            loop 0 = return []
            loop left = do
                r <- safeRecv sock left
                if B.null r
                    then return []
                    else (r :) <$> loop (left - B.length r)
#if MIN_VERSION_network(3,2,12)
    getBackendRecvWith sock = Just $ RecvWith recvAllWith
      where
        recvAllWith n giveUp = loop n []
          where
            done = return . Right . B.concat . reverse
            loop 0 acc = done acc
            loop left acc = do
                r <- Network.recvWith sock left giveUp
                case r of
                    -- Bytes already received are answered, not 'Left'.
                    Left g
                        | null acc -> return $ Left g
                        | otherwise -> done acc
                    Right bs
                        | B.null bs -> done acc
                        | otherwise -> loop (left - B.length bs) (bs : acc)
#endif

instance HasBackend Handle where
    initializeBackend handle = hSetBuffering handle NoBuffering
    getBackend handle =
        Backend
            { backendFlush = hFlush handle
            , backendClose = hClose handle
            , backendSend = B.hPut handle
            , backendRecv = B.hGet handle
            }
