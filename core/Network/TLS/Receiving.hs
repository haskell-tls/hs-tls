{-# LANGUAGE FlexibleContexts #-}

-- |
-- Module      : Network.TLS.Receiving
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Receiving module contains calls related to unmarshalling packets according
-- to the TLS state
module Network.TLS.Receiving (
    processPacket,
    processPacket13,
) where

import Control.Concurrent.MVar
import Control.Monad.State.Strict
import Data.Maybe (fromJust)

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

processPacket :: Context -> Record Plaintext -> IO (Either TLSError Packet)
processPacket _ (Record ProtocolType_AppData _ fragment) = return $ Right $ AppData $ fragmentGetBytes fragment
processPacket _ (Record ProtocolType_Alert _ fragment) = return (Alert `fmapEither` decodeAlerts (fragmentGetBytes fragment))
processPacket ctx (Record ProtocolType_ChangeCipherSpec _ fragment) =
    case decodeChangeCipherSpec $ fragmentGetBytes fragment of
        Left err -> return $ Left err
        Right _ -> do
            switchRxEncryption ctx
            return $ Right ChangeCipherSpec
processPacket ctx (Record ProtocolType_Handshake ver fragment) = do
    keyxchg <-
        getHState ctx >>= \hs -> return (hs >>= hstPendingCipher >>= Just . cipherKeyExchange)
    usingState ctx $ do
        let currentParams =
                CurrentParams
                    { cParamsVersion = ver
                    , cParamsKeyXchgType = keyxchg
                    }
        -- get back the optional continuation, and parse as many handshake record as possible.
        mCont <- gets stHandshakeRecordCont
        modify (\st -> st{stHandshakeRecordCont = Nothing})
        hss <- parseMany currentParams mCont (fragmentGetBytes fragment)
        return $ Handshake hss
  where
    parseMany currentParams mCont bs =
        case fromMaybe decodeHandshakeRecord mCont bs of
            GotError err -> throwError err
            GotPartial cont ->
                modify (\st -> st{stHandshakeRecordCont = Just cont}) >> return []
            GotSuccess (ty, content) ->
                either throwError (return . (: [])) $ decodeHandshake currentParams ty content
            GotSuccessRemaining (ty, content) left ->
                case decodeHandshake currentParams ty content of
                    Left err -> throwError err
                    Right hh -> (hh :) <$> parseMany currentParams Nothing left
processPacket _ _ = return $ Left (Error_Packet_Parsing "unknown protocol type")

switchRxEncryption :: Context -> IO ()
switchRxEncryption ctx =
    usingHState ctx (gets hstPendingRxState) >>= \rx ->
        modifyMVar_ (ctxRxState ctx) (\_ -> return $ fromJust rx)

----------------------------------------------------------------

processPacket13 :: Context -> Record Plaintext -> IO (Either TLSError Packet13)
processPacket13 _ (Record ProtocolType_ChangeCipherSpec _ _) = return $ Right ChangeCipherSpec13
processPacket13 _ (Record ProtocolType_AppData _ fragment) = return $ Right $ AppData13 $ fragmentGetBytes fragment
processPacket13 _ (Record ProtocolType_Alert _ fragment) = return (Alert13 `fmapEither` decodeAlerts (fragmentGetBytes fragment))
processPacket13 ctx (Record ProtocolType_Handshake _ fragment) = usingState ctx $ do
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
processPacket13 _ _ = return $ Left (Error_Packet_Parsing "unknown protocol type")
