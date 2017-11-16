{-# LANGUAGE CPP #-}
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
    , showBytesHex
    , module Data.Bits
    , module Data.List
    , module Data.Ord
    , module Data.Word
    , module Control.Monad
#if !MIN_VERSION_base(4,8,0)
    , sortOn
#endif
    ) where

import qualified Control.Applicative
import qualified Data.Monoid

import           Data.Bits
import           Data.ByteArray.Encoding as B
import           Data.ByteString (ByteString)
import           Data.List
import           Data.Ord
import           Data.Word
import qualified Prelude
import           Control.Monad

showBytesHex :: ByteString -> Prelude.String
showBytesHex bs = Prelude.show (B.convertToBase B.Base16 bs :: ByteString)


#if !MIN_VERSION_base(4,8,0)
sortOn :: Ord b => (a -> b) -> [a] -> [a]
sortOn f =
  map snd . sortBy (comparing fst) . map (\x -> let y = f x in y `seq` (y, x))
#endif
