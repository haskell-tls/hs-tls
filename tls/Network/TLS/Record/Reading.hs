-- | TLS record layer in Rx direction
module Network.TLS.Record.Reading (
    recvRecord12,
    recvRecord13,
) where

import qualified Data.ByteString as B

import Network.TLS.Context.Internal
import Network.TLS.Hooks
import Network.TLS.Imports
import Network.TLS.Packet
import Network.TLS.Record
import Network.TLS.Struct
import Network.TLS.Types

----------------------------------------------------------------

getMyPlainLimit :: Context -> IO Int
getMyPlainLimit ctx = do
    msiz <- getMyRecordLimit ctx
    return $ case msiz of
        Nothing -> defaultRecordSizeLimit
        Just siz -> siz

getRecord
    :: Context
    -> Header
    -> ByteString
    -> IO (Either TLSError (Record Plaintext))
getRecord ctx header content = do
    withLog ctx $ \logging -> loggingIORecv logging header content
    lim <- getMyPlainLimit ctx
    runRxRecordState ctx $ do
        let erecord = rawToRecord header $ fragmentCiphertext content
        decryptRecord erecord lim

----------------------------------------------------------------

exceedsTLSCiphertext :: Int -> Word16 -> Bool
exceedsTLSCiphertext overhead actual =
    -- In TLS 1.3, overhead is included one more byte for content type.
    fromIntegral actual > defaultRecordSizeLimit + overhead

-- | recvRecord receive a full TLS record (header + data), from the other side.
--
-- The record is disengaged from the record layer
recvRecord12
    :: Context
    -- ^ TLS context
    -> IO (Either TLSError (Record Plaintext))
recvRecord12 ctx =
    readExactBytes ctx 5 >>= either (return . Left) (recvLengthE . decodeHeader)
  where
    recvLengthE = either (return . Left) recvLength

    recvLength header@(Header _ _ readlen) = do
        -- RFC 5246 Section 7.2.2
        -- A TLSCiphertext record was received that had a length more
        -- than 2^14+2048 bytes, or a record decrypted to a
        -- TLSCompressed record with more than 2^14+1024 bytes.  This
        -- message is always fatal and should never be observed in
        -- communication between proper implementations (except when
        -- messages were corrupted in the network).
        if exceedsTLSCiphertext 2048 readlen
            then return $ Left maximumSizeExceeded
            else
                readExactBytes ctx (fromIntegral readlen)
                    >>= either (return . Left) (getRecord ctx header)

recvRecord13 :: Context -> IO (Either TLSError (Record Plaintext))
recvRecord13 ctx = readExactBytes ctx 5 >>= either (return . Left) (recvLengthE . decodeHeader)
  where
    recvLengthE = either (return . Left) recvLength
    recvLength header@(Header _ _ readlen) = do
        -- RFC 8446 Section 5.2:
        -- An AEAD algorithm used in TLS 1.3 MUST NOT produce an
        -- expansion greater than 255 octets.  An endpoint that
        -- receives a record from its peer with TLSCiphertext.length
        -- larger than 2^14 + 256 octets MUST terminate the connection
        -- with a "record_overflow" alert.  This limit is derived from
        -- the maximum TLSInnerPlaintext length of 2^14 octets + 1
        -- octet for ContentType + the maximum AEAD expansion of 255
        -- octets.
        if exceedsTLSCiphertext 256 readlen
            then return $ Left maximumSizeExceeded
            else
                readExactBytes ctx (fromIntegral readlen)
                    >>= either (return . Left) (getRecord ctx header)

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
