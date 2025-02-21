{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.TranscriptHash (
    transcriptHash,
    transcriptHashWith,
    updateTranscriptHash,
    updateTranscriptHash13HRR,
    foldTranscriptHash,
    generateFinished,
) where

import Control.Monad.State
import qualified Data.ByteString as B

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Handshake.State
import Network.TLS.Imports
import Network.TLS.Packet
import Network.TLS.Struct
import Network.TLS.Types

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

generateFinished :: Context -> Version -> Role -> IO ByteString
generateFinished ctx ver role = usingHState ctx $ gets gen
  where
    gen hst = case hstTranscriptHash hst of
        TranscriptHashContext hashCtx ->
            let msecret = fromJust $ hstMainSecret hst
                cipher = fromJust $ hstPendingCipher hst
             in switch ver cipher msecret hashCtx
        HandshakeMessages _ ->
            error "un-initialized handshake digest"
    switch
        | role == ClientRole = generateClientFinished
        | otherwise = generateServerFinished

generateFinished' :: PRF -> ByteString -> ByteString -> HashCtx -> ByteString
generateFinished' prf label mainSecret hashctx = prf mainSecret seed 12
  where
    seed = B.concat [label, hashFinal hashctx]

generateClientFinished
    :: Version
    -> Cipher
    -> ByteString
    -> HashCtx
    -> ByteString
generateClientFinished ver ciph =
    generateFinished' (getPRF ver ciph) "client finished"

generateServerFinished
    :: Version
    -> Cipher
    -> ByteString
    -> HashCtx
    -> ByteString
generateServerFinished ver ciph =
    generateFinished' (getPRF ver ciph) "server finished"
