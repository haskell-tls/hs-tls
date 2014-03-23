-- |
-- Module      : Network.TLS.Backend
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- A Backend represents a unified way to do IO on different
-- types without burdening our calling API with multiple
-- ways to initialize a new context.
--
-- Typically, a backend provides:
-- * a way to read data
-- * a way to write data
-- * a way to close the stream
-- * a way to flush the stream
--
module Network.TLS.Backend
    ( HasBackend(..)
    , Backend(..)
    ) where

import Control.Monad
import Network.Socket (Socket, sClose)
import qualified Network.Socket.ByteString as Socket
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import System.IO (Handle, hSetBuffering, BufferMode(..), hFlush, hClose)

-- | Connection IO backend
data Backend = Backend
    { backendFlush :: IO ()                -- ^ Flush the connection sending buffer, if any.
    , backendClose :: IO ()                -- ^ Close the connection.
    , backendSend  :: ByteString -> IO ()  -- ^ Send a bytestring through the connection.
    , backendRecv  :: Int -> IO ByteString -- ^ Receive specified number of bytes from the connection.
    }

class HasBackend a where
    initializeBackend :: a -> IO ()
    getBackend :: a -> Backend

instance HasBackend Backend where
    initializeBackend _ = return ()
    getBackend = id

instance HasBackend Socket where
    initializeBackend _ = return ()
    getBackend sock = Backend (return ()) (sClose sock) (Socket.sendAll sock) recvAll
      where recvAll n = B.concat `fmap` loop n
              where loop 0    = return []
                    loop left = do
                        r <- Socket.recv sock left
                        if B.null r
                            then return []
                            else liftM (r:) (loop (left - B.length r))

instance HasBackend Handle where
    initializeBackend handle = hSetBuffering handle NoBuffering
    getBackend handle = Backend (hFlush handle) (hClose handle) (B.hPut handle) (B.hGet handle)
