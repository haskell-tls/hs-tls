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

import Network.TLS.Context.Internal
import Network.TLS.Struct
import Network.TLS.Record
import Network.TLS.Packet
import Network.TLS.Wire
import Network.TLS.State
import Network.TLS.Handshake.State
import Network.TLS.Cipher
import Network.TLS.Util

import Data.Byteable

processPacket :: Context -> Record Plaintext -> IO (Either TLSError Packet)

processPacket _ (Record ProtocolType_AppData _ fragment) = return $ Right $ AppData $ toBytes fragment

processPacket _ (Record ProtocolType_Alert _ fragment) = return (Alert `fmapEither` (decodeAlerts $ toBytes fragment))

processPacket ctx (Record ProtocolType_ChangeCipherSpec _ fragment) =
    case decodeChangeCipherSpec $ toBytes fragment of
        Left err -> return $ Left err
        Right _  -> do switchRxEncryption ctx
                       return $ Right ChangeCipherSpec

processPacket ctx (Record ProtocolType_Handshake ver fragment) = do
    keyxchg <- getHState ctx >>= \hs -> return $ (hs >>= hstPendingCipher >>= Just . cipherKeyExchange)
    usingState ctx $ do
        npn     <- getExtensionNPN
        let currentParams = CurrentParams
                            { cParamsVersion     = ver
                            , cParamsKeyXchgType = keyxchg
                            , cParamsSupportNPN  = npn
                            }
        -- get back the optional continuation, and parse as many handshake record as possible.
        mCont <- gets stHandshakeRecordCont
        modify (\st -> st { stHandshakeRecordCont = Nothing })
        hss   <- parseMany currentParams mCont (toBytes fragment)
        return $ Handshake hss
  where parseMany currentParams mCont bs =
            case maybe decodeHandshakeRecord id mCont $ bs of
                GotError err                -> throwError err
                GotPartial cont             -> modify (\st -> st { stHandshakeRecordCont = Just cont }) >> return []
                GotSuccess (ty,content)     ->
                    either throwError (return . (:[])) $ decodeHandshake currentParams ty content
                GotSuccessRemaining (ty,content) left ->
                    case decodeHandshake currentParams ty content of
                        Left err -> throwError err
                        Right hh -> (hh:) `fmap` parseMany currentParams Nothing left

processPacket _ (Record ProtocolType_DeprecatedHandshake _ fragment) =
    case decodeDeprecatedHandshake $ toBytes fragment of
        Left err -> return $ Left err
        Right hs -> return $ Right $ Handshake [hs]

switchRxEncryption :: Context -> IO ()
switchRxEncryption ctx =
    usingHState ctx (gets hstPendingRxState) >>= \rx ->
    liftIO $ modifyMVar_ (ctxRxState ctx) (\_ -> return $ fromJust "rx-state" rx)
