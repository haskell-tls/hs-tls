module Network.TLS.Client (recvData) where

import Control.Monad.Trans
import Network.TLS.Struct
import Network.TLS.Core
import qualified Data.ByteString.Lazy as L

{- | recvData get data out of Data packet, and automatically renegociate if
 - a Handshake ClientHello is received -}
recvData :: MonadIO m => TLSCtx -> m L.ByteString
recvData handle = do
	pkt <- recvPacket handle
	case pkt of
		Right [AppData x] -> return $ L.fromChunks [x]
		Right [Handshake HelloRequest] -> handshake handle >> recvData handle
		Left err          -> error ("error received: " ++ show err)
		_                 -> error "unexpected item"
