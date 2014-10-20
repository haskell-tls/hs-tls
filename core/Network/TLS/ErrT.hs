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
    , Error(..)
    , MonadError(..)
    ) where

#if MIN_VERSION_mtl(2,2,1)
import Control.Monad.Except
import Control.Monad.Error.Class (Error(..))
runErrT :: ExceptT e m a -> m (Either e a)
runErrT = runExceptT
type ErrT = ExceptT
#else
import Control.Monad.Error
runErrT = runErrorT
type ErrT = ErrorT
#endif

