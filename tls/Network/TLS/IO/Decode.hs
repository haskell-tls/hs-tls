{-# LANGUAGE FlexibleContexts #-}

module Network.TLS.IO.Decode (
    decodePacket12,
    decodePacket13,
) where

import Control.Concurrent.MVar
import Control.Monad.State.Strict

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.ErrT
import Network.TLS.Handshake.State
import Network.TLS.Imports
import Network.TLS.Packet
import Network.TLS.Packet13
import Network.TLS.Record
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Util
import Network.TLS.Wire

decodePacket12 :: Context -> Record Plaintext -> IO (Either TLSError Packet)
decodePacket12 _ (Record ProtocolType_AppData _ fragment) = return $ Right $ AppData $ fragmentGetBytes fragment
decodePacket12 _ (Record ProtocolType_Alert _ fragment) = return (Alert `fmapEither` decodeAlerts (fragmentGetBytes fragment))
decodePacket12 ctx (Record ProtocolType_ChangeCipherSpec _ fragment) =
    case decodeChangeCipherSpec $ fragmentGetBytes fragment of
        Left err -> return $ Left err
        Right _ -> do
            switchRxEncryption ctx
            return $ Right ChangeCipherSpec
decodePacket12 ctx (Record ProtocolType_Handshake ver fragment) = do
    keyxchg <-
        getHState ctx >>= \hs -> return (hs >>= hstPendingCipher >>= Just . cipherKeyExchange)
    usingState ctx $ do
        let currentParams =
                CurrentParams
                    { cParamsVersion = ver
                    , cParamsKeyXchgType = keyxchg
                    }
        -- get back the optional continuation, and parse as many handshake record as possible.
        mCont <- gets stHandshakeRecordCont12
        modify (\st -> st{stHandshakeRecordCont12 = Nothing})
        hss <- parseMany currentParams mCont (fragmentGetBytes fragment)
        return $ Handshake hss
  where
    parseMany currentParams mCont bs =
        case fromMaybe decodeHandshakeRecord mCont bs of
            GotError err -> throwError err
            GotPartial cont ->
                modify (\st -> st{stHandshakeRecordCont12 = Just cont}) >> return []
            GotSuccess (ty, content) ->
                either throwError (return . (: [])) $ decodeHandshake currentParams ty content
            GotSuccessRemaining (ty, content) left ->
                case decodeHandshake currentParams ty content of
                    Left err -> throwError err
                    Right hh -> (hh :) <$> parseMany currentParams Nothing left
decodePacket12 _ _ = return $ Left (Error_Packet_Parsing "unknown protocol type")

switchRxEncryption :: Context -> IO ()
switchRxEncryption ctx =
    usingHState ctx (gets hstPendingRxState) >>= \rx ->
        modifyMVar_ (ctxRxRecordState ctx) (\_ -> return $ fromJust rx)

----------------------------------------------------------------

decodePacket13 :: Context -> Record Plaintext -> IO (Either TLSError Packet13)
decodePacket13 _ (Record ProtocolType_ChangeCipherSpec _ fragment) =
    case decodeChangeCipherSpec $ fragmentGetBytes fragment of
        Left err -> return $ Left err
        Right _ -> return $ Right ChangeCipherSpec13
decodePacket13 _ (Record ProtocolType_AppData _ fragment) = return $ Right $ AppData13 $ fragmentGetBytes fragment
decodePacket13 _ (Record ProtocolType_Alert _ fragment) = return (Alert13 `fmapEither` decodeAlerts (fragmentGetBytes fragment))
decodePacket13 ctx (Record ProtocolType_Handshake _ fragment) = usingState ctx $ do
    mCont <- gets stHandshakeRecordCont13
    modify (\st -> st{stHandshakeRecordCont13 = Nothing})
    hss <- parseMany mCont (fragmentGetBytes fragment)
    return $ Handshake13 hss
  where
    parseMany mCont bs =
        case fromMaybe decodeHandshakeRecord13 mCont bs of
            GotError err -> throwError err
            GotPartial cont ->
                modify (\st -> st{stHandshakeRecordCont13 = Just cont}) >> return []
            GotSuccess (ty, content) ->
                either throwError (return . (: [])) $ decodeHandshake13 ty content
            GotSuccessRemaining (ty, content) left ->
                case decodeHandshake13 ty content of
                    Left err -> throwError err
                    Right hh -> (hh :) <$> parseMany Nothing left
decodePacket13 _ _ = return $ Left (Error_Packet_Parsing "unknown protocol type")
