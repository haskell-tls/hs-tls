{-# LANGUAGE OverloadedStrings #-}

module ThreadSpec where

import Control.Concurrent
import Control.Concurrent.Async
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as L
import Data.Foldable (traverse_)
import Network.TLS
import Test.Hspec
import Test.Hspec.QuickCheck

import API
import Arbitrary ()
import Run

spec :: Spec
spec = do
    describe "thread safety" $ do
        prop "can read/write concurrently" $ \params ->
            runTLSPipe params tlsClient tlsServer

tlsClient :: Chan ByteString -> Context -> IO ()
tlsClient queue ctx = do
    handshake ctx
    checkCtxFinished ctx
    runReaderWriters ctx "server-value" "client-value"
    d <- readChan queue
    sendData ctx (L.fromChunks [d])
    byeBye ctx

tlsServer :: Context -> Chan [ByteString] -> IO ()
tlsServer ctx queue = do
    handshake ctx
    checkCtxFinished ctx
    runReaderWriters ctx "client-value" "server-value"
    d <- recvData ctx
    writeChan queue [d]
    bye ctx

runReaderWriters :: Context -> ByteString -> L.ByteString -> IO ()
runReaderWriters ctx r w =
    -- run concurrently 10 readers and 10 writers on the same context
    let workers = concat $ replicate 10 [recvDataAssert ctx r, sendData ctx w]
     in runConcurrently $ traverse_ Concurrently workers
