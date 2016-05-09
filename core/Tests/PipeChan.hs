{-# LANGUAGE CPP #-}
-- create a similar concept than a unix pipe.
module PipeChan
    ( PipeChan(..)
    , newPipe
    , runPipe
    , readPipeA
    , readPipeB
    , writePipeA
    , writePipeB
    ) where

#if __GLASGOW_HASKELL__ < 710
import Control.Applicative
#endif

import Control.Concurrent.Chan
import Control.Concurrent
import Control.Monad (forever)
import Data.ByteString (ByteString)
import Data.IORef
import qualified Data.ByteString as B

-- | represent a unidirectional pipe with a buffered read channel and a write channel
data UniPipeChan = UniPipeChan (Chan ByteString) (Chan ByteString)

newUniPipeChan = UniPipeChan <$> newChan <*> newChan

runUniPipe (UniPipeChan r w) = forkIO $ forever $ readChan r >>= writeChan w

getReadUniPipe (UniPipeChan r _)  = r
getWriteUniPipe (UniPipeChan _ w) = w

-- | Represent a bidirectional pipe with 2 nodes A and B
data PipeChan = PipeChan (IORef ByteString) (IORef ByteString) UniPipeChan UniPipeChan

newPipe = PipeChan <$> newIORef B.empty <*> newIORef B.empty <*> newUniPipeChan <*> newUniPipeChan

runPipe (PipeChan _ _ cToS sToC) = runUniPipe cToS >> runUniPipe sToC

readPipeA (PipeChan _ b _ s) sz = readBuffered b (getWriteUniPipe s) sz
writePipeA (PipeChan _ _ c _)   = writeChan $ getWriteUniPipe c

readPipeB (PipeChan b _ c _) sz = readBuffered b (getWriteUniPipe c) sz
writePipeB (PipeChan _ _ _ s)   = writeChan $ getReadUniPipe s

-- helper to read buffered data.
readBuffered buf chan sz = do
    left <- readIORef buf
    if B.length left >= sz
        then do
            let (ret, nleft) = B.splitAt sz left
            writeIORef buf nleft
            return ret
        else do
            let newSize = (sz - B.length left)
            newData <- readChan chan
            writeIORef buf newData
            remain <- readBuffered buf chan newSize
            return (left `B.append` remain)
