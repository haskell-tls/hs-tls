{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Network.TLS.Handshake.Signature
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.Signature
    ( getHashAndASN1
    ) where

import Crypto.PubKey.HashDescr
import Network.TLS.Context
import Network.TLS.Struct

import Control.Monad.State

import qualified Data.ByteString as B

getHashAndASN1 :: MonadIO m => (HashAlgorithm, SignatureAlgorithm) -> m HashDescr
getHashAndASN1 hashSig = do
  case hashSig of
    (HashSHA224, SignatureRSA) -> return hashDescrSHA224
    (HashSHA256, SignatureRSA) -> return hashDescrSHA256
    (HashSHA384, SignatureRSA) -> return hashDescrSHA384
    (HashSHA512, SignatureRSA) -> return hashDescrSHA512
    _                          -> throwCore $ Error_Misc "unsupported hash/sig algorithm"


