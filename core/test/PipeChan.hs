{-# LANGUAGE RecordWildCards #-}

-- create a similar concept than a unix pipe.
module PipeChan (
    PipeChan (..),
    newPipe,
    runPipe,
    readPipeC,
    readPipeS,
    writePipeC,
    writePipeS,
) where

import Control.Concurrent
import Control.Monad (forever)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.IORef

----------------------------------------------------------------

-- | represent a unidirectional pipe with a buffered read channel and
-- a write channel
data UniPipeChan = UniPipeChan
    { getReadUniPipe :: Chan ByteString
    , getWriteUniPipe :: Chan ByteString
    }

newUniPipeChan :: IO UniPipeChan
newUniPipeChan = UniPipeChan <$> newChan <*> newChan

runUniPipe :: UniPipeChan -> IO ThreadId
runUniPipe UniPipeChan{..} =
    forkIO $
        forever $
            readChan getReadUniPipe >>= writeChan getWriteUniPipe

----------------------------------------------------------------

-- | Represent a bidirectional pipe with 2 nodes A and B
data PipeChan = PipeChan
    { fromC :: IORef ByteString
    , fromS :: IORef ByteString
    , c2s :: UniPipeChan
    , s2c :: UniPipeChan
    }

newPipe :: IO PipeChan
newPipe =
    PipeChan
        <$> newIORef B.empty
        <*> newIORef B.empty
        <*> newUniPipeChan
        <*> newUniPipeChan

runPipe :: PipeChan -> IO (ThreadId, ThreadId)
runPipe PipeChan{..} = (,) <$> runUniPipe c2s <*> runUniPipe s2c

readPipeC :: PipeChan -> Int -> IO ByteString
readPipeC PipeChan{..} sz = readBuffered fromS (getWriteUniPipe s2c) sz

writePipeC :: PipeChan -> ByteString -> IO ()
writePipeC PipeChan{..} = writeChan $ getWriteUniPipe c2s

readPipeS :: PipeChan -> Int -> IO ByteString
readPipeS PipeChan{..} sz = readBuffered fromC (getWriteUniPipe c2s) sz

writePipeS :: PipeChan -> ByteString -> IO ()
writePipeS PipeChan{..} = writeChan $ getReadUniPipe s2c

-- helper to read buffered data.
readBuffered :: IORef ByteString -> Chan ByteString -> Int -> IO ByteString
readBuffered ref chan sz = do
    left <- readIORef ref
    if B.length left >= sz
        then do
            let (ret, nleft) = B.splitAt sz left
            writeIORef ref nleft
            return ret
        else do
            let newSize = sz - B.length left
            newData <- readChan chan
            writeIORef ref newData
            remain <- readBuffered ref chan newSize
            return (left `B.append` remain)
