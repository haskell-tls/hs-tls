{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.TranscriptHash (
    transcriptHash,
    transcriptHashWith,
    updateTranscriptHash,
    updateTranscriptHash13HRR,
    transitTranscriptHash,
) where

import Control.Monad.State
import qualified Data.ByteString as B

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Handshake.State
import Network.TLS.Imports

transitTranscriptHash :: Hash -> HandshakeM ()
transitTranscriptHash hashAlg = modify' $ \hst ->
    hst
        { hstTransHashState = case hstTransHashState hst of
            TransHashState0 -> error "transitTranscriptHash"
            TransHashState1 ch -> TransHashState2 $ hashUpdate (hashInit hashAlg) ch
            TransHashState2 hctx -> TransHashState2 hctx -- 2nd SH
        }

updateTranscriptHash :: ByteString -> HandshakeM ()
updateTranscriptHash eh = modify' $ \hst ->
    hst
        { hstTransHashState = case hstTransHashState hst of
            TransHashState0 -> TransHashState1 eh
            TransHashState1 _ch -> error "updateTranscriptHash"
            TransHashState2 hctx -> TransHashState2 $ hashUpdate hctx eh
        }

-- When a HelloRetryRequest is sent or received, the existing
-- transcript must be wrapped in a "message_hash" construct.  See RFC
-- 8446 section 4.4.1.  This applies to key-schedule computations as
-- well as the ones for PSK binders.
updateTranscriptHash13HRR :: HandshakeM ()
updateTranscriptHash13HRR = do
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

transcriptHash :: MonadIO m => Context -> m ByteString
transcriptHash ctx = do
    hst <- fromJust <$> getHState ctx
    case hstTransHashState hst of
        TransHashState2 hashCtx -> return $ hashFinal hashCtx
        _ -> error "transcriptHash"

transcriptHashWith :: MonadIO m => Context -> Hash -> ByteString -> m ByteString
transcriptHashWith ctx hashAlg bs = do
    hst <- fromJust <$> getHState ctx
    case hstTransHashState hst of
        -- When server checks PSK binding in non HRR case, the state
        -- if TransHashState1.
        TransHashState0 -> return $ hash hashAlg bs
        TransHashState2 hashCtx -> return $ hashFinal $ hashUpdate hashCtx bs
        _ -> error "transcriptHashWith"
