-- |
-- Module      : Network.TLS.ErrT
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- a simple compat ErrorT and other error stuff
{-# LANGUAGE CPP #-}
module Network.TLS.ErrT
    ( runErrT
    , ErrT
    , MonadError(..)
    ) where

import Control.Monad.Except (MonadError(..))
import Control.Monad.Trans.Except (ExceptT, runExceptT)

runErrT :: ExceptT e m a -> m (Either e a)
runErrT = runExceptT
type ErrT = ExceptT
