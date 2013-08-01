-- |
-- Module      : Network.TLS.Receiving
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Receiving module contains calls related to unmarshalling packets according
-- to the TLS state
--
module Network.TLS.Receiving
    ( processPacket
    ) where

import Control.Monad.State
import Control.Monad.Error
import Control.Concurrent.MVar

import Network.TLS.Context
import Network.TLS.Struct
import Network.TLS.Record
import Network.TLS.Packet
import Network.TLS.State
import Network.TLS.Handshake.State
import Network.TLS.Cipher
import Network.TLS.Util

returnEither :: Either TLSError a -> TLSSt a
returnEither (Left err) = throwError err
returnEither (Right a)  = return a

processPacket :: Context -> Record Plaintext -> IO (Either TLSError Packet)

processPacket _ (Record ProtocolType_AppData _ fragment) = return $ Right $ AppData $ fragmentGetBytes fragment

processPacket _ (Record ProtocolType_Alert _ fragment) = return (Alert `fmapEither` (decodeAlerts $ fragmentGetBytes fragment))

processPacket ctx (Record ProtocolType_ChangeCipherSpec _ fragment) =
    case decodeChangeCipherSpec $ fragmentGetBytes fragment of
        Left err -> return $ Left err
        Right _  -> do switchRxEncryption ctx
                       return $ Right ChangeCipherSpec

processPacket ctx (Record ProtocolType_Handshake ver fragment) = do
    keyxchg <- getHState ctx >>= \hs -> return $ (hs >>= hstPendingCipher >>= Just . cipherKeyExchange)
    usingState ctx $ do
        npn     <- getExtensionNPN
        let currentparams = CurrentParams
                            { cParamsVersion     = ver
                            , cParamsKeyXchgType = keyxchg
                            , cParamsSupportNPN  = npn
                            }
        handshakes <- returnEither (decodeHandshakes $ fragmentGetBytes fragment)
        hss <- forM handshakes $ \(ty, content) -> do
            case decodeHandshake currentparams ty content of
                    Left err -> throwError err
                    Right hs -> return hs
        return $ Handshake hss

processPacket _ (Record ProtocolType_DeprecatedHandshake _ fragment) =
    case decodeDeprecatedHandshake $ fragmentGetBytes fragment of
        Left err -> return $ Left err
        Right hs -> return $ Right $ Handshake [hs]

switchRxEncryption :: Context -> IO ()
switchRxEncryption ctx =
    usingHState ctx (gets hstPendingRxState) >>= \rx ->
    liftIO $ modifyMVar_ (ctxRxState ctx) (\_ -> return $ fromJust "rx-state" rx)
