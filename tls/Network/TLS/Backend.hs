-- | A Backend represents a unified way to do IO on different
-- types without burdening our calling API with multiple
-- ways to initialize a new context.
--
-- Typically, a backend provides:
-- * a way to read data
-- * a way to write data
-- * a way to close the stream
-- * a way to flush the stream
module Network.TLS.Backend (
    HasBackend (..),
    Backend (..),
) where

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
    -- ^ Receive specified number of bytes from the connection.
    }

class HasBackend a where
    initializeBackend :: a -> IO ()
    getBackend :: a -> Backend

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

instance HasBackend Handle where
    initializeBackend handle = hSetBuffering handle NoBuffering
    getBackend handle =
        Backend
            { backendFlush = hFlush handle
            , backendClose = hClose handle
            , backendSend = B.hPut handle
            , backendRecv = B.hGet handle
            }
