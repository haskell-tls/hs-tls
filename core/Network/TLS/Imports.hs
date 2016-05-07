-- |
-- Module      : Network.TLS.Imports
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Imports
    (
    -- generic exports
      module E
    -- project definition
    , Bytes
    , showBytesHex
    ) where

import qualified Control.Applicative as E
import qualified Data.Monoid as E

import qualified Data.ByteString as B
import           Data.ByteArray.Encoding as B

type Bytes = B.ByteString

showBytesHex :: Bytes -> String
showBytesHex bs = show (B.convertToBase B.Base16 bs :: Bytes)
