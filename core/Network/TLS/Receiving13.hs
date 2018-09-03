{-# LANGUAGE FlexibleContexts #-}

-- |
-- Module      : Network.TLS.Receiving13
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Receiving module contains calls related to unmarshalling packets according
-- to the TLS state
--
module Network.TLS.Receiving13
       ( processPacket13
       ) where

import Control.Monad.State

import Network.TLS.Context.Internal
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.ErrT
import Network.TLS.Record.Types13
import Network.TLS.Packet
import Network.TLS.Packet13
import Network.TLS.Wire
import Network.TLS.State
import Network.TLS.Util
import Network.TLS.Imports

processPacket13 :: Context -> Record13 -> IO (Either TLSError Packet13)
processPacket13 _ (Record13 ContentType_ChangeCipherSpec _) = return $ Right ChangeCipherSpec13
processPacket13 _ (Record13 ContentType_AppData fragment) = return $ Right $ AppData13 fragment
processPacket13 _ (Record13 ContentType_Alert fragment) = return (Alert13 `fmapEither` decodeAlerts fragment)
processPacket13 ctx (Record13 ContentType_Handshake fragment) = usingState ctx $ do
    mCont <- gets stHandshakeRecordCont13
    modify (\st -> st { stHandshakeRecordCont13 = Nothing })
    hss <- parseMany mCont fragment
    return $ Handshake13 hss
  where parseMany mCont bs =
            case fromMaybe decodeHandshakeRecord13 mCont bs of
                GotError err                -> throwError err
                GotPartial cont             -> modify (\st -> st { stHandshakeRecordCont13 = Just cont }) >> return []
                GotSuccess (ty,content)     ->
                    either throwError (return . (:[])) $ decodeHandshake13 ty content
                GotSuccessRemaining (ty,content) left ->
                    case decodeHandshake13 ty content of
                        Left err -> throwError err
                        Right hh -> (hh:) `fmap` parseMany Nothing left
