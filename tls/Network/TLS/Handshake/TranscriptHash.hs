{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.TranscriptHash (
    transcriptHash,
    transcriptHashWith,
    updateTranscriptHash,
    updateTranscriptHash13HRR,
    foldTranscriptHash,
) where

import Control.Monad.State
import qualified Data.ByteString as B

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Handshake.State
import Network.TLS.Imports

-- When a HelloRetryRequest is sent or received, the existing transcript must be
-- wrapped in a "message_hash" construct.  See RFC 8446 section 4.4.1.  This
-- applies to key-schedule computations as well as the ones for PSK binders.
updateTranscriptHash13HRR :: HandshakeM ()
updateTranscriptHash13HRR = do
    cipher <- getPendingCipher
    foldTranscriptHash (cipherHash cipher) foldFunc
  where
    foldFunc dig =
        -- Handshake message:
        -- typ <-len-> body
        -- 254 0 0 len hash(CH1)
        B.concat
            [ "\254\0\0"
            , B.singleton (fromIntegral $ B.length dig)
            , dig
            ]

transcriptHash :: MonadIO m => Context -> m ByteString
transcriptHash ctx = do
    hst <- fromJust <$> getHState ctx
    case hstTranscriptHash hst of
        TranscriptHashContext hashCtx -> return $ hashFinal hashCtx
        HandshakeMessages _ -> error "un-initialized handshake digest"

transcriptHashWith :: MonadIO m => Context -> ByteString -> m ByteString
transcriptHashWith ctx bs = do
    hst <- fromJust <$> getHState ctx
    case hstTranscriptHash hst of
        TranscriptHashContext hashCtx -> return $ hashFinal $ hashUpdate hashCtx bs
        HandshakeMessages _ -> error "un-initialized handshake digest"

updateTranscriptHash :: ByteString -> HandshakeM ()
updateTranscriptHash content = modify $ \hs ->
    hs
        { hstTranscriptHash = case hstTranscriptHash hs of
            HandshakeMessages bytes -> HandshakeMessages (content : bytes)
            TranscriptHashContext hashCtx -> TranscriptHashContext $ hashUpdate hashCtx content
        }

-- | Compress the whole transcript with the specified function.  Function @f@
-- takes the handshake digest as input and returns an encoded handshake message
-- to replace the transcript with.
foldTranscriptHash :: Hash -> (ByteString -> ByteString) -> HandshakeM ()
foldTranscriptHash hashAlg f = modify $ \hs ->
    case hstTranscriptHash hs of
        HandshakeMessages bytes ->
            let hashCtx = foldl hashUpdate (hashInit hashAlg) $ reverse bytes
                folded = f (hashFinal hashCtx)
             in hs
                    { hstTranscriptHash = HandshakeMessages [folded]
                    , hstHandshakeMessages = [folded]
                    }
        TranscriptHashContext hashCtx ->
            let folded = f (hashFinal hashCtx)
                hashCtx' = hashUpdate (hashInit hashAlg) folded
             in hs
                    { hstTranscriptHash = TranscriptHashContext hashCtx'
                    , hstHandshakeMessages = [folded]
                    }
