{-# LANGUAGE CPP #-}
module Tests.Common where

import System.IO
import Test.QuickCheck

{- main -}
myQuickCheckArgs = Args
	{ replay     = Nothing
	, maxSuccess = 500
	, maxDiscard = 2000
	, maxSize    = 500
#if MIN_VERSION_QuickCheck(2,3,0)
	, chatty     = True
#endif
	}

run_test n t =
	putStr ("  " ++ n ++ " ... ") >> hFlush stdout >> quickCheckWith myQuickCheckArgs t
