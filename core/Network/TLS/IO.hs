{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Network.TLS.IO
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.IO
    ( checkValid
    , ConnectionNotEstablished(..)
    , sendPacket
    , recvPacket
    ) where

import Network.TLS.Context
import Network.TLS.Struct
import Network.TLS.Record
import Network.TLS.Packet
import Network.TLS.Sending
import Network.TLS.Receiving
import Data.Data
import qualified Data.ByteString as B
import Data.ByteString.Char8 ()

import Data.IORef
import Control.Monad.State
import Control.Exception (throwIO, Exception())
import System.IO.Error (mkIOError, eofErrorType)

data ConnectionNotEstablished = ConnectionNotEstablished
    deriving (Show,Eq,Typeable)

instance Exception ConnectionNotEstablished

checkValid :: MonadIO m => Context -> m ()
checkValid ctx = do
    established <- ctxEstablished ctx
    unless established $ liftIO $ throwIO ConnectionNotEstablished
    eofed <- ctxEOF ctx
    when eofed $ liftIO $ throwIO $ mkIOError eofErrorType "data" Nothing Nothing

readExact :: MonadIO m => Context -> Int -> m Bytes
readExact ctx sz = do
    hdrbs <- liftIO $ contextRecv ctx sz
    when (B.length hdrbs < sz) $ do
        setEOF ctx
        if B.null hdrbs
            then throwCore Error_EOF
            else throwCore (Error_Packet ("partial packet: expecting " ++ show sz ++ " bytes, got: " ++ (show $B.length hdrbs)))
    return hdrbs

-- | recvRecord receive a full TLS record (header + data), from the other side.
--
-- The record is disengaged from the record layer
recvRecord :: MonadIO m => Bool    -- ^ flag to enable SSLv2 compat ClientHello reception
                        -> Context -- ^ TLS context
                        -> m (Either TLSError (Record Plaintext))
recvRecord compatSSLv2 ctx
#ifdef SSLV2_COMPATIBLE
    | compatSSLv2 = do
        header <- readExact ctx 2
        if B.head header < 0x80
            then readExact ctx 3 >>= either (return . Left) recvLength . decodeHeader . B.append header
            else either (return . Left) recvDeprecatedLength $ decodeDeprecatedHeaderLength header
#endif
    | otherwise = readExact ctx 5 >>= either (return . Left) recvLength . decodeHeader
        where recvLength header@(Header _ _ readlen)
                | readlen > 16384 + 2048 = return $ Left maximumSizeExceeded
                | otherwise              = readExact ctx (fromIntegral readlen) >>= getRecord header
#ifdef SSLV2_COMPATIBLE
              recvDeprecatedLength readlen
                | readlen > 1024 * 4     = return $ Left maximumSizeExceeded
                | otherwise              = do
                    content <- readExact ctx (fromIntegral readlen)
                    case decodeDeprecatedHeader readlen content of
                        Left err     -> return $ Left err
                        Right header -> getRecord header content
#endif
              maximumSizeExceeded = Error_Protocol ("record exceeding maximum size", True, RecordOverflow)
              getRecord :: MonadIO m => Header -> Bytes -> m (Either TLSError (Record Plaintext))
              getRecord header content = do
                    liftIO $ (loggingIORecv $ ctxLogging ctx) header content
                    runRxState ctx $ disengageRecord $ rawToRecord header (fragmentCiphertext content)


-- | receive one packet from the context that contains 1 or
-- many messages (many only in case of handshake). if will returns a
-- TLSError if the packet is unexpected or malformed
recvPacket :: MonadIO m => Context -> m (Either TLSError Packet)
recvPacket ctx = do
    compatSSLv2 <- ctxHasSSLv2ClientHello ctx
    erecord     <- recvRecord compatSSLv2 ctx
    case erecord of
        Left err     -> return $ Left err
        Right record -> do
            pktRecv <- processPacket ctx record
            pkt <- case pktRecv of
                    Right (Handshake hss) ->
                        ctxWithHooks ctx $ \hooks ->
                            liftIO (mapM (hookRecvHandshake hooks) hss) >>= return . Right . Handshake
                    _                     -> return pktRecv
            case pkt of
                Right p -> liftIO $ (loggingPacketRecv $ ctxLogging ctx) $ show p
                _       -> return ()
            when compatSSLv2 $ ctxDisableSSLv2ClientHello ctx
            return pkt

-- | Send one packet to the context
sendPacket :: MonadIO m => Context -> Packet -> m ()
sendPacket ctx pkt = do
    -- in ver <= TLS1.0, block ciphers using CBC are using CBC residue as IV, which can be guessed
    -- by an attacker. Hence, an empty packet is sent before a normal data packet, to
    -- prevent guessability.
    withEmptyPacket <- liftIO $ readIORef $ ctxNeedEmptyPacket ctx
    when (isNonNullAppData pkt && withEmptyPacket) $ sendPacket ctx $ AppData B.empty

    liftIO $ (loggingPacketSent $ ctxLogging ctx) (show pkt)
    edataToSend <- liftIO (writePacket ctx pkt)
    case edataToSend of
        Left err         -> throwCore err
        Right dataToSend -> do
            liftIO $ (loggingIOSent $ ctxLogging ctx) dataToSend
            liftIO $ contextSend ctx dataToSend
  where isNonNullAppData (AppData b) = not $ B.null b
        isNonNullAppData _           = False
