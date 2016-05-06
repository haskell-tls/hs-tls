{-# LANGUAGE CPP #-}
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

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import System.IO (Handle, hSetBuffering, BufferMode(..), hFlush, hClose)

#ifdef INCLUDE_NETWORK
import Control.Monad
import qualified Network.Socket as Network (Socket, sClose)
import qualified Network.Socket.ByteString as Network
import qualified Data.Streaming.Network as Network (safeRecv)
#endif

#ifdef INCLUDE_HANS
import qualified Data.ByteString.Lazy as L
import qualified Hans.NetworkStack as Hans
#endif

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

#ifdef INCLUDE_NETWORK
instance HasBackend Network.Socket where
    initializeBackend _ = return ()
    getBackend sock = Backend (return ()) (Network.sClose sock) (Network.sendAll sock) recvAll
      where recvAll n = B.concat `fmap` loop n
              where loop 0    = return []
                    loop left = do
                        r <- Network.safeRecv sock left
                        if B.null r
                            then return []
                            else liftM (r:) (loop (left - B.length r))
#endif

#ifdef INCLUDE_HANS
instance HasBackend Hans.Socket where
    initializeBackend _ = return ()
    getBackend sock = Backend (return ()) (Hans.close sock) sendAll recvAll
      where sendAll x = do
              amt <- fromIntegral `fmap` Hans.sendBytes sock (L.fromStrict x)
              if (amt == 0) || (amt == B.length x)
                 then return ()
                 else sendAll (B.drop amt x)
            recvAll n = loop (fromIntegral n) L.empty
            loop    0 acc = return (L.toStrict acc)
            loop left acc = do
                r <- Hans.recvBytes sock left
                if L.null r
                   then loop 0 acc
                   else loop (left - L.length r) (acc `L.append` r)
#endif

instance HasBackend Handle where
    initializeBackend handle = hSetBuffering handle NoBuffering
    getBackend handle = Backend (hFlush handle) (hClose handle) (B.hPut handle) (B.hGet handle)
