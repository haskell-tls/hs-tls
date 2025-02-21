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
transitTranscriptHash hashAlg = modify $ \hst ->
    hst
        { hstTranscriptHash = case hstTranscriptHash hst of
            TranscriptHash0 -> error "transitTranscriptHash: TranscriptHash0"
            TranscriptHash1 ch -> TranscriptHash2 $ hashUpdate (hashInit hashAlg) ch
            TranscriptHash2 hctx -> TranscriptHash2 hctx -- 2nd SH
        }

updateTranscriptHash :: ByteString -> HandshakeM ()
updateTranscriptHash eh = modify $ \hst ->
    hst
        { hstTranscriptHash = case hstTranscriptHash hst of
            TranscriptHash0 -> TranscriptHash1 eh
            TranscriptHash1 ch -> TranscriptHash1 (ch <> eh) -- EndOfEarlyData
            TranscriptHash2 hctx -> TranscriptHash2 $ hashUpdate hctx eh
        }

-- When a HelloRetryRequest is sent or received, the existing
-- transcript must be wrapped in a "message_hash" construct.  See RFC
-- 8446 section 4.4.1.  This applies to key-schedule computations as
-- well as the ones for PSK binders.
updateTranscriptHash13HRR :: HandshakeM ()
updateTranscriptHash13HRR = do
    cipher <- getPendingCipher
    let hashAlg = cipherHash cipher
    modify $ \hs ->
        hs
            { hstTranscriptHash = case hstTranscriptHash hs of
                TranscriptHash2 hctx ->
                    let hashCH = hashFinal hctx
                        len = B.length hashCH
                        ch' = wrap len hashCH
                     in TranscriptHash2 $ hashUpdate (hashInit hashAlg) ch'
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
    case hstTranscriptHash hst of
        TranscriptHash2 hashCtx -> return $ hashFinal hashCtx
        _ -> error "un-initialized handshake digest"

transcriptHashWith :: MonadIO m => Context -> ByteString -> m ByteString
transcriptHashWith ctx bs = do
    hst <- fromJust <$> getHState ctx
    case hstTranscriptHash hst of
        TranscriptHash2 hashCtx -> return $ hashFinal $ hashUpdate hashCtx bs
        _ -> error "un-initialized handshake digest"
