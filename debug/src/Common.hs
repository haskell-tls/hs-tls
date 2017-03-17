module Common
    ( readNumber
    ) where

import Control.Monad

import Data.Char (isDigit)

import Numeric (showHex)

import Network.TLS

readNumber :: (Num a, Read a) => String -> Maybe a
readNumber s
    | all isDigit s = Just $ read s
    | otherwise     = Nothing
