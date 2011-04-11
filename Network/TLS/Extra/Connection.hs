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

import Crypto.Random
import Control.Applicative ((<$>))
import Control.Exception
import Data.Char

import System.IO

import Network.BSD
import Network.Socket
import Network.TLS

-- | open a TCP client connection to a destination and port description (number or name)
-- 
connectionClient :: CryptoRandomGen g => String -> String -> TLSParams -> g -> IO TLSCtx
connectionClient s p params rng = do
	pn <- if and $ map isDigit $ p
		then return $ fromIntegral $ (read p :: Int)
		else servicePort <$> getServiceByName p "tcp"
        he <- getHostByName s

	h  <- bracketOnError (socket AF_INET Stream defaultProtocol) sClose $ \sock -> do
		connect sock (SockAddrInet pn (head $ hostAddresses he))
		socketToHandle sock ReadWriteMode
	client params rng h
