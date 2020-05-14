{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Record.Layer (
    RecordLayer(..)
  , newTransparentRecordLayer
  ) where

import Network.TLS.Imports
import Network.TLS.Record
import Network.TLS.Struct

import qualified Data.ByteString as B

data RecordLayer bytes = RecordLayer {
    -- Writing.hs
    recordEncode    :: Record Plaintext -> IO (Either TLSError bytes)
  , recordEncode13  :: Record Plaintext -> IO (Either TLSError bytes)
  , recordSendBytes :: bytes -> IO ()

    -- Reading.hs
  , recordRecv      :: Bool -> Int -> IO (Either TLSError (Record Plaintext))
  , recordRecv13    :: IO (Either TLSError (Record Plaintext))
  }

newTransparentRecordLayer :: Eq ann
                          => IO ann -> ([(ann, ByteString)] -> IO ())
                          -> IO (Either TLSError ByteString)
                          -> RecordLayer [(ann, ByteString)]
newTransparentRecordLayer get send recv = RecordLayer {
    recordEncode    = transparentEncodeRecord get
  , recordEncode13  = transparentEncodeRecord get
  , recordSendBytes = transparentSendBytes send
  , recordRecv      = \_ _ -> transparentRecvRecord recv
  , recordRecv13    = transparentRecvRecord recv
  }

transparentEncodeRecord :: IO ann -> Record Plaintext -> IO (Either TLSError [(ann, ByteString)])
transparentEncodeRecord _ (Record ProtocolType_ChangeCipherSpec _ _) =
    return $ Right []
transparentEncodeRecord _ (Record ProtocolType_Alert _ _) =
    -- all alerts are silent and must be transported externally based on
    -- TLS exceptions raised by the library
    return $ Right []
transparentEncodeRecord get (Record _ _ frag) =
    get >>= \a -> return $ Right [(a, fragmentGetBytes frag)]

transparentSendBytes :: Eq ann => ([(ann, ByteString)] -> IO ()) -> [(ann, ByteString)] -> IO ()
transparentSendBytes send input = send
    [ (a, bs) | (a, frgs) <- compress input
              , let bs = B.concat frgs
              , not (B.null bs)
    ]

transparentRecvRecord :: IO (Either TLSError ByteString)
                      -> IO (Either TLSError (Record Plaintext))
transparentRecvRecord recv =
    fmap (Record ProtocolType_Handshake TLS12 . fragmentPlaintext) <$> recv

compress :: Eq ann => [(ann, val)] -> [(ann, [val])]
compress []         = []
compress ((a,v):xs) =
    let (ys, zs) = span ((== a) . fst) xs
     in (a, v : map snd ys) : compress zs
