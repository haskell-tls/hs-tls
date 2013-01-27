-- |
-- Module      : Network.TLS.Extension
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- basic extensions are defined in RFC 6066
--
module Network.TLS.Extension
    ( Extension(..)
    , supportedExtensions
    -- all extensions ID supported
    , extensionID_ServerName
    , extensionID_MaxFragmentLength
    , extensionID_SecureRenegotiation
    , extensionID_NextProtocolNegotiation
    -- all implemented extensions
    , ServerNameType(..)
    , ServerName(..)
    , MaxFragmentLength(..)
    , MaxFragmentEnum(..)
    , SecureRenegotiation(..)
    , NextProtocolNegotiation(..)
    ) where

import Control.Applicative ((<$>))
import Control.Monad

import Data.Word
import Data.Maybe (fromMaybe)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

import Network.TLS.Struct (ExtensionID)
import Network.TLS.Wire
import Network.BSD (HostName)

extensionID_ServerName, extensionID_MaxFragmentLength
                      , extensionID_SecureRenegotiation
                      , extensionID_NextProtocolNegotiation :: ExtensionID
extensionID_ServerName              = 0x0
extensionID_MaxFragmentLength       = 0x1
extensionID_SecureRenegotiation     = 0xff01
extensionID_NextProtocolNegotiation = 0x3374

-- | all supported extensions by the implementation
supportedExtensions :: [ExtensionID]
supportedExtensions = [ extensionID_ServerName
                      , extensionID_MaxFragmentLength
                      , extensionID_SecureRenegotiation
                      , extensionID_NextProtocolNegotiation
                      ]

-- | Extension class to transform bytes to and from a high level Extension type.
class Extension a where
    extensionID     :: a -> ExtensionID
    extensionDecode :: Bool -> ByteString -> Maybe a
    extensionEncode :: a -> ByteString

-- | Server Name extension including the name type and the associated name.
-- the associated name decoding is dependant of its name type.
-- name type = 0 : hostname
data ServerName = ServerName [ServerNameType]
    deriving (Show,Eq)

data ServerNameType = ServerNameHostName HostName
                    | ServerNameOther    (Word8, ByteString)
                    deriving (Show,Eq)

instance Extension ServerName where
    extensionID _ = extensionID_ServerName
    extensionEncode (ServerName l) = runPut $ putOpaque16 (runPut $ mapM_ encodeNameType l)
        where encodeNameType (ServerNameHostName hn)       = putWord8 0  >> putOpaque16 (BC.pack hn) -- FIXME: should be puny code conversion
              encodeNameType (ServerNameOther (nt,opaque)) = putWord8 nt >> putBytes opaque
    extensionDecode _ = runGetMaybe (getWord16 >>= \len -> getList (fromIntegral len) getServerName >>= return . ServerName)
        where getServerName = do
                  ty    <- getWord8
                  sname <- getOpaque16
                  return (1+2+B.length sname, case ty of
                      0 -> ServerNameHostName $ BC.unpack sname -- FIXME: should be puny code conversion
                      _ -> ServerNameOther (ty, sname))

-- | Max fragment extension with length from 512 bytes to 4096 bytes
data MaxFragmentLength = MaxFragmentLength MaxFragmentEnum
    deriving (Show,Eq)
data MaxFragmentEnum = MaxFragment512 | MaxFragment1024 | MaxFragment2048 | MaxFragment4096
    deriving (Show,Eq)

instance Extension MaxFragmentLength where
    extensionID _ = extensionID_MaxFragmentLength
    extensionEncode (MaxFragmentLength e) = B.singleton $ marshallSize e
        where marshallSize MaxFragment512  = 1
              marshallSize MaxFragment1024 = 2
              marshallSize MaxFragment2048 = 3
              marshallSize MaxFragment4096 = 4
    extensionDecode _ = runGetMaybe (MaxFragmentLength . unmarshallSize <$> getWord8)
        where unmarshallSize 1 = MaxFragment512
              unmarshallSize 2 = MaxFragment1024
              unmarshallSize 3 = MaxFragment2048
              unmarshallSize 4 = MaxFragment4096
              unmarshallSize n = error ("unknown max fragment size " ++ show n)

-- | Secure Renegotiation
data SecureRenegotiation = SecureRenegotiation ByteString (Maybe ByteString)
    deriving (Show,Eq)

instance Extension SecureRenegotiation where
    extensionID _ = extensionID_SecureRenegotiation
    extensionEncode (SecureRenegotiation cvd svd) =
        runPut $ putOpaque8 (cvd `B.append` fromMaybe B.empty svd)
    extensionDecode isServerHello = runGetMaybe getSecureReneg
        where getSecureReneg = do
                  opaque <- getOpaque8
                  if isServerHello
                     then let (cvd, svd) = B.splitAt (B.length opaque `div` 2) opaque
                           in return $ SecureRenegotiation cvd (Just svd)
                     else return $ SecureRenegotiation opaque Nothing

-- | Next Protocol Negotiation
data NextProtocolNegotiation = NextProtocolNegotiation [ByteString]
    deriving (Show,Eq)

instance Extension NextProtocolNegotiation where
    extensionID _ = extensionID_NextProtocolNegotiation
    extensionEncode (NextProtocolNegotiation bytes) =
        runPut $ mapM_ putOpaque8 bytes
    extensionDecode _ = runGetMaybe (NextProtocolNegotiation <$> getNPN)
        where getNPN = do
                 avail <- remaining
                 case avail of
                     0 -> return []
                     _ -> do liftM2 (:) getOpaque8 getNPN
