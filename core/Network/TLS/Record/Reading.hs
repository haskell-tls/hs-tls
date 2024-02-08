-- | TLS record layer in Rx direction
module Network.TLS.Record.Reading (
    recvRecord,
    recvRecord13,
) where

import qualified Data.ByteString as B

import Network.TLS.Context.Internal
import Network.TLS.ErrT
import Network.TLS.Hooks
import Network.TLS.Imports
import Network.TLS.Packet
import Network.TLS.Record
import Network.TLS.Struct

----------------------------------------------------------------

exceeds :: Integral ty => Context -> Int -> ty -> Bool
exceeds ctx overhead actual =
    case ctxFragmentSize ctx of
        Nothing -> False
        Just sz -> fromIntegral actual > sz + overhead

getRecord
    :: Context
    -> Int
    -> Header
    -> ByteString
    -> IO (Either TLSError (Record Plaintext))
getRecord ctx appDataOverhead header@(Header pt _ _) content = do
    withLog ctx $ \logging -> loggingIORecv logging header content
    runRxRecordState ctx $ do
        r <- decodeRecordM header content
        let Record _ _ fragment = r
        when (exceeds ctx overhead $ B.length (fragmentGetBytes fragment)) $
            throwError contentSizeExceeded
        return r
  where
    overhead = if pt == ProtocolType_AppData then appDataOverhead else 0

decodeRecordM :: Header -> ByteString -> RecordM (Record Plaintext)
decodeRecordM header content = disengageRecord erecord
  where
    erecord = rawToRecord header (fragmentCiphertext content)

contentSizeExceeded :: TLSError
contentSizeExceeded = Error_Protocol "record content exceeding maximum size" RecordOverflow

----------------------------------------------------------------

-- | recvRecord receive a full TLS record (header + data), from the other side.
--
-- The record is disengaged from the record layer
recvRecord
    :: Context
    -- ^ TLS context
    -> Int
    -- ^ number of AppData bytes to accept above normal maximum size
    -> IO (Either TLSError (Record Plaintext))
recvRecord ctx appDataOverhead =
    readExactBytes ctx 5 >>= either (return . Left) (recvLengthE . decodeHeader)
  where
    recvLengthE = either (return . Left) recvLength

    recvLength header@(Header _ _ readlen)
        | exceeds ctx 2048 readlen = return $ Left maximumSizeExceeded
        | otherwise =
            readExactBytes ctx (fromIntegral readlen)
                >>= either (return . Left) (getRecord ctx appDataOverhead header)

recvRecord13 :: Context -> IO (Either TLSError (Record Plaintext))
recvRecord13 ctx = readExactBytes ctx 5 >>= either (return . Left) (recvLengthE . decodeHeader)
  where
    recvLengthE = either (return . Left) recvLength
    recvLength header@(Header _ _ readlen)
        | exceeds ctx 256 readlen = return $ Left maximumSizeExceeded
        | otherwise =
            readExactBytes ctx (fromIntegral readlen)
                >>= either (return . Left) (getRecord ctx 0 header)

maximumSizeExceeded :: TLSError
maximumSizeExceeded = Error_Protocol "record exceeding maximum size" RecordOverflow

----------------------------------------------------------------

readExactBytes :: Context -> Int -> IO (Either TLSError ByteString)
readExactBytes ctx sz = do
    hdrbs <- contextRecv ctx sz
    if B.length hdrbs == sz
        then return $ Right hdrbs
        else do
            setEOF ctx
            return . Left $
                if B.null hdrbs
                    then Error_EOF
                    else
                        Error_Packet
                            ( "partial packet: expecting "
                                ++ show sz
                                ++ " bytes, got: "
                                ++ show (B.length hdrbs)
                            )
