-- |
-- Module      : Network.TLS.Backend
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Backend represent a unified way to do IO on differents
-- types without burdening our calling API with multiples
-- way to initialize a new context.
--
-- Typically any backend much implement:
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
import System.IO

-- | Connection IO backend
data Backend = Backend
    { backendFlush :: IO ()                -- ^ Flush the connection sending buffer, if any.
    , backendClose :: IO ()                -- ^ Close the connection.
    , backendSend  :: ByteString -> IO ()  -- ^ Send a bytestring through the connection.
    , backendRecv  :: Int -> IO ByteString -- ^ Receive specified number of bytes from the connection.
    }

class HasBackend a where
    getBackend :: a -> Backend

instance HasBackend Backend where
    getBackend = id

instance HasBackend Socket where
    getBackend sock = Backend (return ()) (sClose sock) (Socket.sendAll sock) recvAll
      where recvAll n = B.concat `fmap` loop n
              where loop 0    = return []
                    loop left = do
                        r <- Socket.recv sock left
                        liftM (r:) (loop (left - B.length r))

instance HasBackend Handle where
    getBackend handle = Backend (hFlush handle) (hClose handle) (B.hPut handle) (B.hGet handle)
