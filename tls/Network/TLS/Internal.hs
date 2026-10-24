{-# OPTIONS_HADDOCK hide #-}

module Network.TLS.Internal (
    module Network.TLS.Extension,
    module Network.TLS.IO.Decode,
    module Network.TLS.IO.Encode,
    module Network.TLS.Packet,
    module Network.TLS.Packet13,
    module Network.TLS.Struct,
    module Network.TLS.Struct13,
    module Network.TLS.Types,
    module Network.TLS.Wire,
    module Network.TLS.X509,
    sendPacket12,
    recvPacket12,
    makeCipherShowPretty,
    paddingIsValid,
    setTxSequence,
    setRxSequence,
) where

import Control.Concurrent.MVar
import Data.IORef
import Data.Word (Word64)

import Network.TLS.Context.Internal (Context (..))
import Network.TLS.Core (recvPacket12, sendPacket12)
import Network.TLS.Extension
import Network.TLS.Extra.Cipher
import Network.TLS.IO.Decode
import Network.TLS.IO.Encode
import Network.TLS.Packet
import Network.TLS.Packet13
import Network.TLS.Record.Decrypt (paddingIsValid)
import Network.TLS.Record.State (MacState (..), RecordState (..))
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types
import Network.TLS.Wire
import Network.TLS.X509 hiding (Certificate)

----------------------------------------------------------------

makeCipherShowPretty :: IO ()
makeCipherShowPretty = writeIORef globalCipherDict ciphersuite_all

-- | Setting the sequence number of the next record sent, for testing.
setTxSequence :: Context -> Word64 -> IO ()
setTxSequence ctx = setSequence (ctxTxRecordState ctx)

-- | Setting the sequence number of the next record received, for testing.
setRxSequence :: Context -> Word64 -> IO ()
setRxSequence ctx = setSequence (ctxRxRecordState ctx)

setSequence :: MVar RecordState -> Word64 -> IO ()
setSequence ref sqn = modifyMVar_ ref $ \st -> return st{stMacState = MacState sqn}
