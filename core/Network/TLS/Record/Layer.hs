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

data RecordLayer = RecordLayer {
    -- Sending.hs and Sending13.hs
    encodeRecord :: Record Plaintext -> IO (Either TLSError ByteString)
    -- IO.hs
  , sendBytes    :: ByteString -> IO ()
    -- IO.hs
  , recvRecord   :: IO (Either TLSError (Record Plaintext))
  }

newTransparentRecordLayer :: (ByteString -> IO ()) -> IO ByteString -> RecordLayer
newTransparentRecordLayer send recv = RecordLayer {
    encodeRecord = transparentEncodeRecord
  , sendBytes    = transparentSendBytes send
  , recvRecord   = transparentRecvRecord recv
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
transparentRecvRecord recv = do
    bs <- recv
    return $ Right $ Record ProtocolType_Handshake TLS12 (fragmentPlaintext bs)
