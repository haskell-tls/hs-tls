{-# LANGUAGE NoImplicitPrelude #-}

module Network.TLS.Imports (
    -- generic exports
    ByteString,
    (<&>),
    module Control.Applicative,
    module Control.Monad,
    module Data.Bits,
    module Data.List,
    module Data.Maybe,
    module Data.Semigroup,
    module Data.Ord,
    module Data.Word,
    -- project definition
    showBytesHex,
) where

import Data.ByteString (ByteString)
import Data.ByteString.Char8 ()

-- instance
import Data.Functor

import Control.Applicative
import Control.Monad
import Data.Bits
import Data.List
import Data.Maybe
import Data.Ord
import Data.Semigroup
import Data.Word

import Data.ByteArray.Encoding as B
import qualified Prelude as P

showBytesHex :: ByteString -> P.String
showBytesHex bs = P.show (B.convertToBase B.Base16 bs :: ByteString)
