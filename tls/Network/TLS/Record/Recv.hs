{-# LANGUAGE TypeApplications #-}

-- | TLS record layer in Rx direction
module Network.TLS.Record.Recv (
    recvRecord12,
    recvRecord13,
) where

import Control.Concurrent.STM
import qualified Control.Exception as E
import qualified Data.ByteString as B
import Data.IORef

import Network.TLS.Backend
import Network.TLS.Context.Internal
import Network.TLS.Hooks
import Network.TLS.Imports
import Network.TLS.Measurement
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
    readExactBytes ctx False 5
        >>= either (return . Left) (recvLengthE . (decodeHeader >=> checkType))
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
                readExactBytes ctx True (fromIntegral readlen)
                    >>= either (return . Left) (getRecord ctx header)

recvRecord13 :: Context -> IO (Either TLSError (Record Plaintext))
recvRecord13 ctx =
    readExactBytes ctx False 5
        >>= either (return . Left) (recvLengthE . (decodeHeader >=> checkType))
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
                readExactBytes ctx True (fromIntegral readlen)
                    >>= either (return . Left) (getRecord13 header)
    -- RFC 9846 Section 4.2.10: a server that rejected early data skips the
    -- records it cannot deprotect, until the first one it can.
    getRecord13 header@(Header ty _ readlen) content = do
        erecord <- getRecord ctx header content
        case erecord of
            Left (Error_Protocol _ BadRecordMac) -> do
                skipped <- skipEarlyData ctx (fromIntegral readlen)
                if skipped then recvRecord13 ctx else return erecord
            Right _ | ty == ProtocolType_AppData -> do
                established <- ctxEstablished ctx
                case established of
                    EarlyDataNotAllowed _ -> setEstablished ctx NotEstablished
                    _ -> return ()
                return erecord
            _ -> return erecord

maximumSizeExceeded :: TLSError
maximumSizeExceeded = Error_Protocol "record exceeding maximum size" RecordOverflow

-- RFC 8446 Section 5: a record of an unexpected type is answered with
-- unexpected_message.  Checked on the header, before the body is read, so
-- that what is no TLS record at all -- an SSLv2 ClientHello, say, whose first
-- byte reads as type 0x80 and whose length can ask for bytes that never
-- come -- is answered at once rather than when the peer gives up.
checkType :: Header -> Either TLSError Header
checkType header@(Header ty _ _)
    | ty `elem` known = Right header
    | otherwise =
        Left $ Error_Packet_unexpected (show ty) " expected: TLS record type"
  where
    known =
        [ ProtocolType_ChangeCipherSpec
        , ProtocolType_Alert
        , ProtocolType_Handshake
        , ProtocolType_AppData
        ]

----------------------------------------------------------------

readExactBytes :: Context -> Bool -> Int -> IO (Either TLSError ByteString)
readExactBytes ctx inRecord sz = do
    ctxRxBrokenBy ctx >>= mapM_ (throwBroken "a previous receive failed")
    mgiveUp <- fmap snd <$> readIORef (ctxRxGiveUp ctx)
    hdrbs <- recv mgiveUp `E.catch` broken
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
  where
    recv mgiveUp = case (mgiveUp, ctxBackendRecvWith ctx) of
        (Just giveUp, Just (RecvWith recvWith)) -> do
            updateMeasure ctx $ addBytesReceived sz
            let inside n = do
                    r <- recvWith n $ giveUpInside giveUp
                    gaveUp <- fired $ giveUpInside giveUp
                    case r of
                        Right bs | B.length bs == n || not gaveUp -> return bs
                        _ -> do
                            let e = PostHandshake $ Error_Misc "gave up inside a record"
                            setRxBroken ctx $ E.toException e
                            E.throwIO e
            if inRecord
                then inside sz
                else do
                    r <- recvWith sz $ giveUpBetween giveUp
                    case r of
                        Left () -> E.throwIO GaveUp
                        Right bs
                            | B.length bs == sz || B.null bs -> return bs
                            | otherwise -> do
                                -- Begun: the rest is given up on only inside.
                                gaveUp <- fired $ giveUpBetween giveUp
                                if gaveUp
                                    then (bs <>) <$> inside (sz - B.length bs)
                                    else return bs
        _ -> contextRecv ctx sz
    fired stm = atomically $ (True <$ stm) `orElse` return False
    -- A broken transport ends the connection.  Another exception inside a
    -- record leaves the stream there, so later receives fail at once.
    -- Both wake up those waiting for a post-handshake authentication.
    broken :: E.SomeException -> IO a
    broken e
        | isJust (E.fromException @E.IOException e) = setEOF ctx >> E.throwIO e
        | isJust (E.fromException @GaveUp e) = E.throwIO e
        | inRecord = setRxBroken ctx e >> E.throwIO e
        | otherwise = E.throwIO e
