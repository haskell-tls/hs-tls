module Network.TLS.Server (recvData) where

import Control.Monad.Trans
import Network.TLS.Core
import Network.TLS.Struct
import qualified Data.ByteString.Lazy as L

{- | recvData get data out of Data packet, and automatically renegociate if
 - a Handshake ClientHello is received -}
recvData :: MonadIO m => TLSCtx -> m L.ByteString
recvData ctx = do
	pkt <- recvPacket ctx
	case pkt of
		Right [Handshake (ClientHello _ _ _ _ _ _)] -> handshake ctx >> recvData ctx
		Right [AppData x] -> return $ L.fromChunks [x]
		Left err          -> error ("error received: " ++ show err)
		_                 -> error "unexpected item"
