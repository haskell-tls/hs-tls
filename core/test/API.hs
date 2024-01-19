{-# LANGUAGE OverloadedStrings #-}

module API where

import Control.Applicative
import Control.Monad
import Data.ByteString (ByteString)
import Data.Maybe
import Network.TLS
import Test.Hspec

checkCtxFinished :: Context -> IO ()
checkCtxFinished ctx = do
    mUnique <- getTLSUnique ctx
    mExporter <- getTLSExporter ctx
    when (isNothing (mUnique <|> mExporter)) $
        fail "unexpected channel binding"

recvDataAssert :: Context -> ByteString -> IO ()
recvDataAssert ctx expected = do
    got <- recvData ctx
    got `shouldBe` expected
