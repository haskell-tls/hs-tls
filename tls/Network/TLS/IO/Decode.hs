{-# LANGUAGE FlexibleContexts #-}

module Network.TLS.IO.Decode (
    decodePacket12,
    decodePacket13,
    checkChangeCipherSpec,
) where

import Control.Concurrent.MVar
import Control.Monad.State.Strict
import qualified Data.ByteString as BS

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
import Network.TLS.Types (Role (..))
import Network.TLS.Util
import Network.TLS.Wire

decodePacket12 :: Context -> Record Plaintext -> IO (Either TLSError Packet)
decodePacket12 _ (Record ProtocolType_AppData _ fragment) = return $ Right $ AppData $ fragmentGetBytes fragment
decodePacket12 _ (Record ProtocolType_Alert _ fragment) = return (Alert `fmapEither` decodeAlerts (fragmentGetBytes fragment))
decodePacket12 ctx (Record ProtocolType_ChangeCipherSpec _ fragment) =
    case checkChangeCipherSpec fragment of
        Left err -> return $ Left err
        Right _ -> do
            switchRxEncryption ctx
            return $ Right ChangeCipherSpec
decodePacket12 ctx (Record ProtocolType_Handshake ver fragment) = do
    mhs <- getHState ctx
    let keyxchg = mhs >>= hstPendingCipher >>= Just . cipherKeyExchange
    usingState ctx $ do
        role <- getRole
        let currentParams =
                CurrentParams
                    { cParamsVersion = ver
                    , cParamsKeyXchgType = keyxchg
                    }
            -- A server has no handshake state until its first ClientHello,
            -- and that is the only message it may receive then (RFC 8446
            -- Section 4).  Any other is answered with unexpected_message
            -- before its body is decoded, rather than with whatever decoding
            -- the body as that type gives.
            expectClientHello = role == ServerRole && isNothing mhs
            decode ty content
                | expectClientHello && ty /= HandshakeType_ClientHello =
                    Left $ Error_Packet_unexpected (show ty) " expected: client hello"
                | otherwise = decodeHandshake currentParams ty content
        -- get back the optional continuation, and parse as many handshake record as possible.
        (mCont, wirebytes) <- gets stHandshakeRecordCont12
        modify' (\st -> st{stHandshakeRecordCont12 = (Nothing, [])})
        (hss, bss) <-
            unzip <$> parseMany decode mCont wirebytes (fragmentGetBytes fragment)
        return $ Handshake hss bss
  where
    parseMany decode mCont wirebytes bs =
        case fromMaybe decodeHandshakeRecord mCont bs of
            GotError err -> throwError err
            GotPartial cont -> do
                modify' (\st -> st{stHandshakeRecordCont12 = (Just cont, bs : wirebytes)})
                return []
            GotSuccess (ty, content) ->
                case decode ty content of
                    Left err -> throwError err
                    Right h -> return [(h, reverse (bs : wirebytes))]
            GotSuccessRemaining (ty, content) left ->
                case decode ty content of
                    Left err -> throwError err
                    Right h -> do
                        hbs <- parseMany decode Nothing [] left
                        let len = BS.length bs - BS.length left
                            bs' = BS.take len bs
                        return ((h, reverse (bs' : wirebytes)) : hbs)
decodePacket12 _ (Record ty _ _) = return $ Left $ unknownProtocolType ty

switchRxEncryption :: Context -> IO ()
switchRxEncryption ctx =
    usingHState ctx (gets hstPendingRxState) >>= \rx ->
        modifyMVar_ (ctxRxRecordState ctx) (\_ -> return $ fromJust rx)

----------------------------------------------------------------

decodePacket13 :: Context -> Record Plaintext -> IO (Either TLSError Packet13)
decodePacket13 _ (Record ProtocolType_ChangeCipherSpec _ fragment) =
    case checkChangeCipherSpec fragment of
        Left err -> return $ Left err
        Right _ -> return $ Right ChangeCipherSpec13
decodePacket13 _ (Record ProtocolType_AppData _ fragment) = return $ Right $ AppData13 $ fragmentGetBytes fragment
decodePacket13 _ (Record ProtocolType_Alert _ fragment) = return (Alert13 `fmapEither` decodeAlerts (fragmentGetBytes fragment))
decodePacket13 ctx (Record ProtocolType_Handshake _ fragment) = usingState ctx $ do
    (mCont, wirebytes) <- gets stHandshakeRecordCont13
    modify' (\st -> st{stHandshakeRecordCont13 = (Nothing, [])})
    (hss, bss) <- unzip <$> parseMany mCont wirebytes (fragmentGetBytes fragment)
    return $ Handshake13 hss bss
  where
    parseMany mCont wirebytes bs =
        case fromMaybe decodeHandshakeRecord13 mCont bs of
            GotError err -> throwError err
            GotPartial cont -> do
                modify' (\st -> st{stHandshakeRecordCont13 = (Just cont, bs : wirebytes)})
                return []
            GotSuccess (ty, content) ->
                case decodeHandshake13 ty content of
                    Left err -> throwError err
                    Right h -> return [(h, reverse (bs : wirebytes))]
            GotSuccessRemaining (ty, content) left ->
                case decodeHandshake13 ty content of
                    Left err -> throwError err
                    Right h -> do
                        hbs <- parseMany Nothing [] left
                        let len = BS.length bs - BS.length left
                            bs' = BS.take len bs
                        return ((h, reverse (bs' : wirebytes)) : hbs)
decodePacket13 _ (Record ty _ _) = return $ Left $ unknownProtocolType ty

-- RFC 8446 Section 5: a record of an unexpected type, including the inner
-- type of a TLS 1.3 record, is answered with unexpected_message.
unknownProtocolType :: ProtocolType -> TLSError
unknownProtocolType ty = Error_Packet_unexpected (show ty) " expected: TLS record type"

-- | A ChangeCipherSpec is the single byte 1.  RFC 8446 Section 5 answers any
-- other value with unexpected_message, and TLS 1.2, which does not say,
-- is answered the same way: a record of two of them included.
checkChangeCipherSpec :: Fragment a -> Either TLSError ()
checkChangeCipherSpec fragment =
    case decodeChangeCipherSpec $ fragmentGetBytes fragment of
        Left _ ->
            Left $
                Error_Packet_unexpected "ChangeCipherSpec" " expected: the single byte 1"
        Right _ -> Right ()
