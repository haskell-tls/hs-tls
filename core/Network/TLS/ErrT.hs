{-# LANGUAGE CPP #-}

-- | A simple compat ErrorT and other error stuff
module Network.TLS.ErrT (
    runErrT,
    ErrT,
    MonadError (..),
) where

import Control.Monad.Except (MonadError (..))
import Control.Monad.Trans.Except (ExceptT, runExceptT)

runErrT :: ExceptT e m a -> m (Either e a)
runErrT = runExceptT
type ErrT = ExceptT
