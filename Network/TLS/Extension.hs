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
    , extensionID_SecureRenegotiation
    , extensionID_NextProtocolNegotiation
    -- all implemented extensions
    , SecureRenegotiation(..)
    , NextProtocolNegotiation(..)
    ) where

import Control.Applicative ((<$>))
import Control.Monad

import Data.Word
import Data.Maybe (fromMaybe)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Network.TLS.Struct (ExtensionID)
import Network.TLS.Wire

extensionID_SecureRenegotiation, extensionID_NextProtocolNegotiation :: ExtensionID
extensionID_SecureRenegotiation = 0xff01
extensionID_NextProtocolNegotiation = 0x3374

-- | all supported extensions by the implementation
supportedExtensions :: [ExtensionID]
supportedExtensions = [ extensionID_SecureRenegotiation
                      , extensionID_NextProtocolNegotiation
                      ]

-- | Extension class to transform bytes to and from a high level Extension type.
class Extension a where
    extensionID     :: a -> ExtensionID
    extensionDecode :: Bool -> ByteString -> Maybe a
    extensionEncode :: a -> ByteString


-- | Server Name including the name type and the associated name.
-- the associated name decoding is dependant of its name type.
-- name type = 0 : hostname
data ServerName = ServerName [(Word8,ByteString)]
    deriving (Show,Eq)

instance Extension ServerName where
    extensionID _ = 0x0
    extensionEncode (ServerName l) = runPut $ mapM_ encodeName l
        where encodeName (nt,opaque) = putWord8 nt >> putOpaque16 opaque
    extensionDecode _ = runGetMaybe (remaining >>= \len -> getList len getServerName >>= return . ServerName)
        where getServerName = do
                  ty    <- getWord8
                  sname <- getOpaque16
                  return (1+2+B.length sname, (ty, sname))

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
