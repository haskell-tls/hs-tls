{-# LANGUAGE OverloadedStrings #-}
module Network.TLS.Handshake.Signature
    ( getHashAndASN1
    ) where

import qualified Crypto.Hash.SHA224 as SHA224
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA384 as SHA384
import qualified Crypto.Hash.SHA512 as SHA512

import Network.TLS.Context
import Network.TLS.Struct

import Control.Monad.State

import qualified Data.ByteString as B

getHashAndASN1 :: MonadIO m => (HashAlgorithm, SignatureAlgorithm) -> m (B.ByteString -> B.ByteString, B.ByteString)
getHashAndASN1 hashSig = do
  case hashSig of
    (HashSHA224, SignatureRSA) ->
      return (SHA224.hash, "\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c")
    (HashSHA256, SignatureRSA) ->
      return (SHA256.hash, "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20")
    (HashSHA384, SignatureRSA) ->
      return (SHA384.hash, "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30")
    (HashSHA512, SignatureRSA) ->
      return (SHA512.hash, "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40")
    _ ->
      throwCore $ Error_Misc "unsupported hash/sig algorithm"


