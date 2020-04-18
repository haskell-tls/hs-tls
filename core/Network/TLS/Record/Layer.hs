{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Record.Layer (
    RecordLayer(..)
  , newTransparentRecordLayer
  ) where

import Network.TLS.Imports
import Network.TLS.Record
import Network.TLS.Struct

import qualified Control.Exception as E
import qualified Data.ByteString as B

data RecordLayer bytes = RecordLayer {
    -- Sending.hs
    recordEncode    :: Record Plaintext -> IO (Either TLSError bytes)

    -- Sending13.hs
  , recordEncode13  :: Record Plaintext -> IO (Either TLSError bytes)

    -- IO.hs
  , recordSendBytes :: bytes -> IO ()
  , recordRecv      :: Bool -> Int -> IO (Either TLSError (Record Plaintext))
  , recordRecv13    :: IO (Either TLSError (Record Plaintext))
  , recordNeedFlush :: Bool
  }

newTransparentRecordLayer :: (ByteString -> IO ()) -> IO ByteString -> RecordLayer ByteString
newTransparentRecordLayer send recv = RecordLayer {
    recordEncode    = transparentEncodeRecord
  , recordEncode13  = transparentEncodeRecord
  , recordSendBytes = transparentSendBytes send
  , recordRecv      = \_ _ -> transparentRecvRecord recv
  , recordRecv13    = transparentRecvRecord recv
  , recordNeedFlush = True
  }

transparentEncodeRecord :: Record Plaintext -> IO (Either TLSError ByteString)
transparentEncodeRecord (Record ProtocolType_ChangeCipherSpec _ _) =
    return $ Right ""
transparentEncodeRecord (Record ProtocolType_Alert _ frag) = do
    let Just desc = valToType (fragmentGetBytes frag `B.index` 1)
    E.throwIO $ Error_Protocol ("transparentEncodeRecord", True, desc)
transparentEncodeRecord (Record _ _ frag) =
    return $ Right $ fragmentGetBytes frag

transparentSendBytes :: (ByteString -> IO ()) -> ByteString -> IO ()
transparentSendBytes _    "" = return ()
transparentSendBytes send bs = send bs

transparentRecvRecord :: IO ByteString -> IO (Either TLSError (Record Plaintext))
transparentRecvRecord recv =
    Right . Record ProtocolType_Handshake TLS12 . fragmentPlaintext <$> recv
