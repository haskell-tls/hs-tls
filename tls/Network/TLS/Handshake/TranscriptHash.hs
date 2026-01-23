{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.TranscriptHash (
    transcriptHash,
    transcriptHashWith,
    transitTranscriptHashI,
    updateTranscriptHash,
    updateTranscriptHashI,
    transitTranscriptHash,
    copyTranscriptHash,
    TranscriptHash (..),
) where

import Control.Monad.State
import qualified Data.ByteString as B

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Handshake.State
import Network.TLS.Imports
import Network.TLS.Parameters
import Network.TLS.State
import Network.TLS.Types

----------------------------------------------------------------

transitTranscriptHash :: Context -> String -> Hash -> Bool -> IO ()
transitTranscriptHash ctx label hashAlg isHRR = do
    usingHState ctx $ modify' $ \hst ->
        hst{hstTransHashState = transit label hashAlg isHRR $ hstTransHashState hst}
    traceTranscriptHash ctx label hstTransHashState

transitTranscriptHashI :: Context -> String -> Hash -> Bool -> IO ()
transitTranscriptHashI ctx label hashAlg isHRR = do
    usingHState ctx $ modify' $ \hst ->
        hst{hstTransHashStateI = transit label hashAlg isHRR $ hstTransHashStateI hst}
    traceTranscriptHash ctx label hstTransHashStateI

transit :: String -> Hash -> Bool -> TransHashState -> TransHashState
transit label _ _ st0@TransHashState0 = error $ "transitTranscriptHash " ++ label ++ " " ++ show st0
transit _ _ _ st2@(TransHashState2 _) = st2
transit _ hashAlg isHRR (TransHashState1 chs)
    | isHRR = TransHashState2 $ hashUpdate (hashInit hashAlg) hsMsg
    | otherwise = TransHashState2 $ hashUpdates (hashInit hashAlg) ch
  where
    ch = chs []
    hsMsg =
        -- Handshake message:
        -- typ <-len-> body
        -- 254 0 0 len hash(CH1)
        B.concat
            [ "\254\0\0"
            , B.singleton len
            , hashedCH
            ]
      where
        hashedCH = hashChunks hashAlg ch
        len = fromIntegral $ B.length hashedCH

----------------------------------------------------------------

updateTranscriptHash :: Context -> String -> ByteString -> IO ()
updateTranscriptHash ctx label eh = do
    usingHState ctx $ modify' $ \hst ->
        hst{hstTransHashState = update eh label $ hstTransHashState hst}
    traceTranscriptHash ctx label hstTransHashState

updateTranscriptHashI :: Context -> String -> ByteString -> IO ()
updateTranscriptHashI ctx label eh = do
    usingHState ctx $ modify' $ \hst ->
        hst{hstTransHashStateI = update eh label $ hstTransHashStateI hst}
    traceTranscriptHash ctx label hstTransHashStateI

update :: ByteString -> String -> TransHashState -> TransHashState
update eh _ TransHashState0 = TransHashState1 (eh :)
update eh _ (TransHashState1 b) = TransHashState1 (b . (eh :))
update eh _ (TransHashState2 hctx) = TransHashState2 $ hashUpdate hctx eh

----------------------------------------------------------------

transcriptHash :: MonadIO m => Context -> String -> m TranscriptHash
transcriptHash ctx label = do
    hst <- fromJust <$> getHState ctx
    let th = calc label $ hstTransHashState hst
    liftIO $ debugTraceKey (ctxDebug ctx) $ adjustLabel label ++ showBytesHex th
    return $ TranscriptHash th

calc :: String -> TransHashState -> ByteString
calc _ (TransHashState2 hashCtx) = hashFinal hashCtx
calc label st = error $ "transcriptHash " ++ label ++ " " ++ show st

----------------------------------------------------------------

transcriptHashWith
    :: MonadIO m => Context -> String -> ByteString -> m TranscriptHash
transcriptHashWith ctx label bs = do
    role <- liftIO $ usingState_ ctx getRole
    let isClient = role == ClientRole
    hst <- fromJust <$> getHState ctx
    let st
            | isClient = hstTransHashStateI hst
            | otherwise = hstTransHashState hst
    let th = calcWith bs label st
    liftIO $ debugTraceKey (ctxDebug ctx) $ adjustLabel label ++ showBytesHex th
    return $ TranscriptHash th

calcWith :: ByteString -> String -> TransHashState -> ByteString
calcWith bs _ (TransHashState2 hashCtx) = hashFinal $ hashUpdate hashCtx bs
calcWith _ label st = error $ "transcriptHashWith " ++ label ++ " " ++ show st

----------------------------------------------------------------

copyTranscriptHash :: Context -> String -> IO ()
copyTranscriptHash ctx label = do
    usingHState ctx $ modify' $ \hst ->
        hst
            { hstTransHashState = hstTransHashStateI hst
            }
    traceTranscriptHash ctx label hstTransHashState

----------------------------------------------------------------

traceTranscriptHash
    :: Context -> String -> (HandshakeState -> TransHashState) -> IO ()
traceTranscriptHash ctx label getField = do
    hst <- fromJust <$> getHState ctx
    debugTraceKey (ctxDebug ctx) $ adjustLabel label ++ show (getField hst)

adjustLabel :: String -> String
adjustLabel label = take 24 (label ++ "                      ")
