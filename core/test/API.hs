{-# LANGUAGE OverloadedStrings #-}

module API where

import Control.Applicative
import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Maybe
import Network.TLS
import Test.Hspec

checkCtxFinished :: Context -> IO ()
checkCtxFinished ctx = do
    mUnique <- getTLSUnique ctx
    mExporter <- getTLSExporter ctx
    when (isNothing (mUnique <|> mExporter)) $
        fail "unexpected channel binding"

-- Terminate the write direction and wait to receive the peer EOF.  This is
-- necessary in situations where we want to confirm the peer status, or to make
-- sure to receive late messages like session tickets.  In the test suite this
-- is used each time application code ends the connection without prior call to
-- 'recvData'.
byeBye :: Context -> IO ()
byeBye ctx = do
    bye ctx
    bs <- recvData ctx
    unless (B.null bs) $ fail "byeBye: unexpected application data"

recvDataAssert :: Context -> ByteString -> IO ()
recvDataAssert ctx expected = do
    got <- recvData ctx
    got `shouldBe` expected
