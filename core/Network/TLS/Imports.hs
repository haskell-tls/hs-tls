-- |
-- Module      : Network.TLS.Imports
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
{-# LANGUAGE NoImplicitPrelude #-}
module Network.TLS.Imports
    (
    -- generic exports
      ByteString
    , Control.Applicative.Applicative(..)
    , (Control.Applicative.<$>)
    , Data.Monoid.Monoid(..)
    -- project definition
    , Bytes
    , showBytesHex
    ) where

import qualified Control.Applicative
import qualified Data.Monoid

import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.ByteArray.Encoding as B
import qualified Prelude

type Bytes = B.ByteString

showBytesHex :: ByteString -> Prelude.String
showBytesHex bs = Prelude.show (B.convertToBase B.Base16 bs :: ByteString)
