module Network.TLS.Record.Layer (
    RecordLayer (..),
    newTransparentRecordLayer,
) where

import Network.TLS.Context
import Network.TLS.Imports
import Network.TLS.Record
import Network.TLS.Struct

import qualified Data.ByteString as B

newTransparentRecordLayer
    :: Eq ann
    => (Context -> IO ann)
    -> ([(ann, ByteString)] -> IO ())
    -> (Context -> IO (Either TLSError ByteString))
    -> RecordLayer [(ann, ByteString)]
newTransparentRecordLayer get send recv =
    RecordLayer
        { recordEncode12 = transparentEncodeRecord get
        , recordEncode13 = transparentEncodeRecord get
        , recordSendBytes = transparentSendBytes send
        , recordRecv12 = \ctx _ -> transparentRecvRecord recv ctx
        , recordRecv13 = transparentRecvRecord recv
        }

transparentEncodeRecord
    :: (Context -> IO ann)
    -> Context
    -> Record Plaintext
    -> IO (Either TLSError [(ann, ByteString)])
transparentEncodeRecord _ _ (Record ProtocolType_ChangeCipherSpec _ _) =
    return $ Right []
transparentEncodeRecord _ _ (Record ProtocolType_Alert _ _) =
    -- all alerts are silent and must be transported externally based on
    -- TLS exceptions raised by the library
    return $ Right []
transparentEncodeRecord get ctx (Record _ _ frag) =
    get ctx >>= \a -> return $ Right [(a, fragmentGetBytes frag)]

transparentSendBytes
    :: Eq ann
    => ([(ann, ByteString)] -> IO ())
    -> Context
    -> [(ann, ByteString)]
    -> IO ()
transparentSendBytes send _ input =
    send
        [ (a, bs) | (a, frgs) <- compress input, let bs = B.concat frgs, not (B.null bs)
        ]

transparentRecvRecord
    :: (Context -> IO (Either TLSError ByteString))
    -> Context
    -> IO (Either TLSError (Record Plaintext))
transparentRecvRecord recv ctx =
    fmap (Record ProtocolType_Handshake TLS12 . fragmentPlaintext) <$> recv ctx

compress :: Eq ann => [(ann, val)] -> [(ann, [val])]
compress [] = []
compress ((a, v) : xs) =
    let (ys, zs) = span ((== a) . fst) xs
     in (a, v : map snd ys) : compress zs
