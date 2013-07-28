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

import Control.Applicative ((<$>))
import Control.Monad.State
import Control.Monad.Error

import Network.TLS.Struct
import Network.TLS.Record
import Network.TLS.Packet
import Network.TLS.State
import Network.TLS.Cipher

returnEither :: Either TLSError a -> TLSSt a
returnEither (Left err) = throwError err
returnEither (Right a)  = return a

processPacket :: Record Plaintext -> TLSSt Packet

processPacket (Record ProtocolType_AppData _ fragment) = return $ AppData $ fragmentGetBytes fragment

processPacket (Record ProtocolType_Alert _ fragment) = return . Alert =<< returnEither (decodeAlerts $ fragmentGetBytes fragment)

processPacket (Record ProtocolType_ChangeCipherSpec _ fragment) = do
    returnEither $ decodeChangeCipherSpec $ fragmentGetBytes fragment
    switchRxEncryption
    return ChangeCipherSpec

processPacket (Record ProtocolType_Handshake ver fragment) = do
    keyxchg <- gets (\st -> case stHandshake st of
                                Nothing  -> Nothing
                                Just hst -> cipherKeyExchange <$> hstPendingCipher hst)
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

processPacket (Record ProtocolType_DeprecatedHandshake _ fragment) =
    case decodeDeprecatedHandshake $ fragmentGetBytes fragment of
        Left err -> throwError err
        Right hs -> return $ Handshake [hs]
