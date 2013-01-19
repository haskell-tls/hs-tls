-- |
-- Module      : Network.TLS.Extra.Connection
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Extra.Connection
    ( connectionClient
    ) where

import Crypto.Random.API
import Control.Applicative ((<$>))
import Control.Exception
import Data.Char

import System.IO

import Network.BSD
import Network.Socket
import Network.TLS

-- | @connectionClient host port param rng@ opens a TCP client connection
-- to a destination host and port description (number or name). For
-- example:
-- 
-- @
-- import Network.TLS.Extra
-- import Crypto.Random
-- ...
--   conn <- (newGenIO::IO SystemRandom) >>= connectionClient 192.168.2.2 7777 defaultParams g
-- @
--
-- will make a new RNG (using system entropy) and connect to IP 192.168.2.2
-- on port 7777.
connectionClient :: CPRG g => String -> String -> TLSParams -> g -> IO Context
connectionClient s p params rng = do
    pn <- if and $ map isDigit $ p
              then return $ fromIntegral $ (read p :: Int)
              else servicePort <$> getServiceByName p "tcp"
    he <- getHostByName s

    h <- bracketOnError (socket AF_INET Stream defaultProtocol) sClose $ \sock -> do
        connect sock (SockAddrInet pn (head $ hostAddresses he))
        socketToHandle sock ReadWriteMode
    contextNewOnHandle h params rng
