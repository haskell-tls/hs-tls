-- | TLS record layer in Tx direction
module Network.TLS.Record.Writing (
    encodeRecord12,
    encodeRecord13,
    sendBytes,
) where

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Hooks
import Network.TLS.Imports
import Network.TLS.Packet
import Network.TLS.Record
import Network.TLS.Struct

import Control.Concurrent.MVar
import Control.Monad.State.Strict
import qualified Data.ByteString as B

encodeRecordM :: Record Plaintext -> RecordM ByteString
encodeRecordM record = do
    erecord <- encryptRecord record
    let (hdr, content) = recordToRaw erecord
    return $ B.concat [encodeHeader hdr, content]

----------------------------------------------------------------

encodeRecord12 :: Context -> Record Plaintext -> IO (Either TLSError ByteString)
encodeRecord12 ctx = prepareRecord12 ctx . encodeRecordM

-- before TLS 1.1, the block cipher IV is made of the residual of the previous block,
-- so we use cstIV as is, however in other case we generate an explicit IV
prepareRecord12 :: Context -> RecordM a -> IO (Either TLSError a)
prepareRecord12 ctx f = do
    txState <- readMVar $ ctxTxRecordState ctx
    let sz = case stCipher txState of
            Nothing -> 0
            Just cipher ->
                if hasRecordIV $ bulkF $ cipherBulk cipher
                    then bulkIVSize $ cipherBulk cipher
                    else 0 -- to not generate IV
    if sz > 0
        then do
            newIV <- getStateRNG ctx sz
            runTxRecordState ctx (modify (setRecordIV newIV) >> f)
        else runTxRecordState ctx f

----------------------------------------------------------------

encodeRecord13 :: Context -> Record Plaintext -> IO (Either TLSError ByteString)
encodeRecord13 ctx = prepareRecord13 ctx . encodeRecordM

prepareRecord13 :: Context -> RecordM a -> IO (Either TLSError a)
prepareRecord13 = runTxRecordState

----------------------------------------------------------------

sendBytes :: Context -> ByteString -> IO ()
sendBytes ctx dataToSend = do
    withLog ctx $ \logging -> loggingIOSent logging dataToSend
    contextSend ctx dataToSend
