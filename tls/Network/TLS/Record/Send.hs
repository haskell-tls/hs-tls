-- | TLS record layer in Tx direction
module Network.TLS.Record.Send (
    encodeRecord12,
    encodeRecord13,
    sendBytes,
) where

import Control.Concurrent.MVar
import qualified Control.Exception as E
import Control.Monad.State.Strict
import qualified Data.ByteString as B

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Hooks
import Network.TLS.Imports
import Network.TLS.Packet
import Network.TLS.Record
import Network.TLS.Struct

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
            runTxRecordState ctx (modify' (setRecordIV newIV) >> f)
        else runTxRecordState ctx f

----------------------------------------------------------------

encodeRecord13 :: Context -> Record Plaintext -> IO (Either TLSError ByteString)
encodeRecord13 ctx = prepareRecord13 ctx . encodeRecordM

prepareRecord13 :: Context -> RecordM a -> IO (Either TLSError a)
prepareRecord13 = runTxRecordState

----------------------------------------------------------------

sendBytes :: Context -> ByteString -> IO ()
sendBytes ctx dataToSend = do
    -- The record state has advanced already, so a failed send leaves the
    -- peer unable to decrypt any later record.  Later sends throw the same
    -- exception, except an asynchronous one, which is not thrown again.
    ctxTxBrokenBy ctx >>= mapM_ (\e -> E.throwIO $ fromMaybe e $ asTLS e)
    withLog ctx $ \logging -> loggingIOSent logging dataToSend
    contextSend ctx dataToSend `E.catch` \e -> setTxBroken ctx e >> E.throwIO e
  where
    asTLS e = case E.fromException e of
        Just (E.SomeAsyncException _) ->
            Just $ E.toException $ PostHandshake $ Error_Misc "a previous send failed"
        Nothing -> Nothing
