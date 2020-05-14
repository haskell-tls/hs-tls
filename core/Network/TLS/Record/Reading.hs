{-# LANGUAGE CPP #-}
-- |
-- Module      : Network.TLS.Record.Reading
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- TLS record layer in Rx direction
--
module Network.TLS.Record.Reading
    ( recvRecord
    , recvRecord13
    ) where

import Control.Monad.Reader
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

getRecord :: Context -> Int -> Header -> ByteString -> IO (Either TLSError (Record Plaintext))
getRecord ctx appDataOverhead header@(Header pt _ _) content = do
    withLog ctx $ \logging -> loggingIORecv logging header content
    runRxState ctx $ do
        r <- decodeRecordM header content
        let Record _ _ fragment = r
        when (exceeds ctx overhead $ B.length (fragmentGetBytes fragment)) $
            throwError contentSizeExceeded
        return r
  where overhead = if pt == ProtocolType_AppData then appDataOverhead else 0

decodeRecordM :: Header -> ByteString -> RecordM (Record Plaintext)
decodeRecordM header content = disengageRecord erecord
   where
     erecord = rawToRecord header (fragmentCiphertext content)

contentSizeExceeded :: TLSError
contentSizeExceeded = Error_Protocol ("record content exceeding maximum size", True, RecordOverflow)

----------------------------------------------------------------

-- | recvRecord receive a full TLS record (header + data), from the other side.
--
-- The record is disengaged from the record layer
recvRecord :: Context -- ^ TLS context
           -> Bool    -- ^ flag to enable SSLv2 compat ClientHello reception
           -> Int     -- ^ number of AppData bytes to accept above normal maximum size
           -> IO (Either TLSError (Record Plaintext))
recvRecord ctx compatSSLv2 appDataOverhead
#ifdef SSLV2_COMPATIBLE
    | compatSSLv2 = readExactBytes ctx 2 >>= either (return . Left) sslv2Header
#endif
    | otherwise = readExactBytes ctx 5 >>= either (return . Left) (recvLengthE . decodeHeader)

        where recvLengthE = either (return . Left) recvLength

              recvLength header@(Header _ _ readlen)
                | exceeds ctx 2048 readlen = return $ Left maximumSizeExceeded
                | otherwise                =
                    readExactBytes ctx (fromIntegral readlen) >>=
                        either (return . Left) (getRecord ctx appDataOverhead header)
#ifdef SSLV2_COMPATIBLE
              sslv2Header header =
                if B.head header >= 0x80
                    then either (return . Left) recvDeprecatedLength $ decodeDeprecatedHeaderLength header
                    else readExactBytes ctx 3 >>=
                            either (return . Left) (recvLengthE . decodeHeader . B.append header)

              recvDeprecatedLength readlen
                | readlen > 1024 * 4     = return $ Left maximumSizeExceeded
                | otherwise              = do
                    res <- readExactBytes ctx (fromIntegral readlen)
                    case res of
                      Left e -> return $ Left e
                      Right content ->
                        let hdr = decodeDeprecatedHeader readlen (B.take 3 content)
                         in either (return . Left) (\h -> getRecord ctx appDataOverhead h content) hdr
#endif

recvRecord13 :: Context -> IO (Either TLSError (Record Plaintext))
recvRecord13 ctx = readExactBytes ctx 5 >>= either (return . Left) (recvLengthE . decodeHeader)
  where recvLengthE = either (return . Left) recvLength
        recvLength header@(Header _ _ readlen)
          | exceeds ctx 256 readlen = return $ Left maximumSizeExceeded
          | otherwise               =
              readExactBytes ctx (fromIntegral readlen) >>=
                 either (return . Left) (getRecord ctx 0 header)

maximumSizeExceeded :: TLSError
maximumSizeExceeded = Error_Protocol ("record exceeding maximum size", True, RecordOverflow)

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
                    else Error_Packet ("partial packet: expecting " ++ show sz ++ " bytes, got: " ++ show (B.length hdrbs))
