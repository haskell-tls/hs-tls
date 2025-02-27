{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.TranscriptHash (
    transcriptHash,
    transcriptHashWith,
    updateTranscriptHash,
    updateTranscriptHash13HRR,
    transitTranscriptHash,
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
import Network.TLS.Types

transitTranscriptHash :: Context -> String -> Hash -> IO ()
transitTranscriptHash ctx label hashAlg = do
    usingHState ctx $ modify' $ \hst ->
        hst
            { hstTransHashState = case hstTransHashState hst of
                TransHashState0 -> error "transitTranscriptHash"
                TransHashState1 ch -> TransHashState2 $ hashUpdate (hashInit hashAlg) ch
                TransHashState2 hctx -> TransHashState2 hctx -- 2nd SH
            }
    traceTranscriptHash ctx label

updateTranscriptHash :: Context -> String -> ByteString -> IO ()
updateTranscriptHash ctx label eh = do
    usingHState ctx $ modify' $ \hst ->
        hst
            { hstTransHashState = case hstTransHashState hst of
                TransHashState0 -> TransHashState1 eh
                TransHashState1 _ch -> error "updateTranscriptHash"
                TransHashState2 hctx -> TransHashState2 $ hashUpdate hctx eh
            }
    traceTranscriptHash ctx label

-- When a HelloRetryRequest is sent or received, the existing
-- transcript must be wrapped in a "message_hash" construct.  See RFC
-- 8446 section 4.4.1.  This applies to key-schedule computations as
-- well as the ones for PSK binders.
updateTranscriptHash13HRR :: Context -> String -> IO ()
updateTranscriptHash13HRR ctx label = do
    usingHState ctx $ do
        cipher <- getPendingCipher
        let hashAlg = cipherHash cipher
        modify' $ \hs ->
            hs
                { hstTransHashState = case hstTransHashState hs of
                    TransHashState2 hctx ->
                        let hashCH = hashFinal hctx
                            len = B.length hashCH
                            ch' = wrap len hashCH
                         in TransHashState2 $ hashUpdate (hashInit hashAlg) ch'
                    _ -> error "updateTranscriptHash13HRR"
                }
    traceTranscriptHash ctx label
  where
    wrap len hashCH =
        -- Handshake message:
        -- typ <-len-> body
        -- 254 0 0 len hash(CH1)
        B.concat
            [ "\254\0\0"
            , B.singleton (fromIntegral len)
            , hashCH
            ]

transcriptHash :: MonadIO m => Context -> String -> m TranscriptHash
transcriptHash ctx label = do
    hst <- fromJust <$> getHState ctx
    case hstTransHashState hst of
        TransHashState2 hashCtx -> do
            let th = hashFinal hashCtx
            liftIO $
                debugTraceKey (ctxDebug ctx) $
                    adjustLabel label ++ showBytesHex th
            return $ TranscriptHash th
        _ -> error "transcriptHash"

transcriptHashWith
    :: MonadIO m => Context -> String -> Hash -> ByteString -> m TranscriptHash
transcriptHashWith ctx label hashAlg bs = do
    hst <- fromJust <$> getHState ctx
    case hstTransHashState hst of
        -- When server checks PSK binding in non HRR case, the state
        -- if TransHashState1.
        TransHashState0 -> do
            let th = hash hashAlg bs
            liftIO $
                debugTraceKey (ctxDebug ctx) $
                    adjustLabel label ++ showBytesHex th
            return $ TranscriptHash th
        TransHashState2 hashCtx -> do
            let th = hashFinal $ hashUpdate hashCtx bs
            liftIO $
                debugTraceKey (ctxDebug ctx) $
                    adjustLabel label ++ showBytesHex th
            return $ TranscriptHash th
        _ -> error "transcriptHashWith"

traceTranscriptHash :: Context -> String -> IO ()
traceTranscriptHash ctx label = do
    hst <- fromJust <$> getHState ctx
    case hstTransHashState hst of
        TransHashState2 hashCtx -> do
            let th = hashFinal hashCtx
            debugTraceKey (ctxDebug ctx) $ adjustLabel label ++ showBytesHex th
        _ -> return ()

adjustLabel :: String -> String
adjustLabel label = take 24 (label ++ "                      ")
