-- | The Wire module is a specialized marshalling/unmarshalling
-- package related to the TLS protocol.  All multibytes values are
-- written as big endian.
module Network.TLS.Parser (
    -- * Types
    GetResult (..),
    GetContinuation,
    ParseError (..),

    -- * Get
    Get,
    runGet,
    runGetErr,
    runGetMaybe,
    tryGet,
    G.remaining,
    G.getWord8,
    getWords8,
    getWord16,
    getWords16,
    getWord24,
    getWord32,
    getWord64,
    G.getBytes,
    getOpaque8,
    getOpaque16,
    getOpaque24,
    getList,
    processBytes,
    G.isEmpty,

    -- * Put
    Put,
    G.runPut,
    G.putWord8,
    putWords8,
    putWord16,
    putWords16,
    putWord24,
    putWord32,
    putWord64,
    putBytes,
    putOpaque8,
    putOpaque16,
    putOpaque24,
    encodeWord16,
    encodeWord32,
    encodeWord64,
) where

import Control.Monad (replicateM, when)
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Serialize.Get (Get)
import qualified Data.Serialize.Get as G
import Data.Serialize.Put (Put)
import qualified Data.Serialize.Put as G
import Data.Word (Word16, Word32, Word64, Word8)

newtype ParseError = ParseError String deriving (Eq, Show)

type GetContinuation a = ByteString -> GetResult a
data GetResult a
    = GotError String
    | GotPartial (GetContinuation a)
    | GotSuccess a
    | GotSuccessRemaining a ByteString

runGet :: String -> Get a -> ByteString -> GetResult a
runGet lbl f = toGetResult <$> G.runGetPartial (G.label lbl f)
  where
    toGetResult (G.Fail err _) = GotError err
    toGetResult (G.Partial cont) = GotPartial (toGetResult <$> cont)
    toGetResult (G.Done r bsLeft)
        | B.null bsLeft = GotSuccess r
        | otherwise = GotSuccessRemaining r bsLeft

runGetErr :: String -> Get a -> ByteString -> Either ParseError a
runGetErr lbl getter b = toSimple $ runGet lbl getter b
  where
    toSimple (GotError err) = Left $ ParseError err
    toSimple (GotPartial _) = Left (ParseError (lbl ++ ": parsing error: partial packet"))
    toSimple (GotSuccessRemaining _ _) = Left (ParseError (lbl ++ ": parsing error: remaining bytes"))
    toSimple (GotSuccess r) = Right r

runGetMaybe :: Get a -> ByteString -> Maybe a
runGetMaybe f = either (const Nothing) Just . G.runGet f

tryGet :: Get a -> ByteString -> Maybe a
tryGet f = either (const Nothing) Just . G.runGet f

getWords8 :: Get [Word8]
getWords8 = G.getWord8 >>= \lenb -> replicateM (fromIntegral lenb) G.getWord8

getWord16 :: Get Word16
getWord16 = G.getWord16be

getWords16 :: Get [Word16]
getWords16 = do
    lenb <- getWord16
    when (odd lenb) $ fail "length for ciphers must be even"
    replicateM (fromIntegral lenb `shiftR` 1) getWord16

getWord24 :: Get Int
getWord24 = do
    a <- fromIntegral <$> G.getWord8
    b <- fromIntegral <$> G.getWord8
    c <- fromIntegral <$> G.getWord8
    return $ (a `shiftL` 16) .|. (b `shiftL` 8) .|. c

getWord32 :: Get Word32
getWord32 = G.getWord32be

getWord64 :: Get Word64
getWord64 = G.getWord64be

getOpaque8 :: Get ByteString
getOpaque8 = G.getWord8 >>= G.getBytes . fromIntegral

getOpaque16 :: Get ByteString
getOpaque16 = getWord16 >>= G.getBytes . fromIntegral

getOpaque24 :: Get ByteString
getOpaque24 = getWord24 >>= G.getBytes

getList :: Int -> Get (Int, a) -> Get [a]
getList totalLen getElement = G.isolate totalLen (getElements totalLen)
  where
    getElements len
        | len < 0 =
            error "list consumed too much data. should never happen with isolate."
        | len == 0 = return []
        | otherwise =
            getElement >>= \(elementLen, a) -> (:) a <$> getElements (len - elementLen)

processBytes :: Int -> Get a -> Get a
processBytes i f = G.isolate i f

putWords8 :: [Word8] -> Put
putWords8 l = do
    G.putWord8 $ fromIntegral $ length l
    mapM_ G.putWord8 l

putWord16 :: Word16 -> Put
putWord16 = G.putWord16be

putWord32 :: Word32 -> Put
putWord32 = G.putWord32be

putWord64 :: Word64 -> Put
putWord64 = G.putWord64be

putWords16 :: [Word16] -> Put
putWords16 l = do
    putWord16 $ 2 * fromIntegral (length l)
    mapM_ putWord16 l

putWord24 :: Int -> Put
putWord24 i = do
    let a = fromIntegral ((i `shiftR` 16) .&. 0xff)
    let b = fromIntegral ((i `shiftR` 8) .&. 0xff)
    let c = fromIntegral (i .&. 0xff)
    mapM_ G.putWord8 [a, b, c]

putBytes :: ByteString -> Put
putBytes = G.putByteString

putOpaque8 :: ByteString -> Put
putOpaque8 b = G.putWord8 (fromIntegral $ B.length b) >> putBytes b

putOpaque16 :: ByteString -> Put
putOpaque16 b = putWord16 (fromIntegral $ B.length b) >> putBytes b

putOpaque24 :: ByteString -> Put
putOpaque24 b = putWord24 (B.length b) >> putBytes b

encodeWord16 :: Word16 -> ByteString
encodeWord16 = G.runPut . putWord16

encodeWord32 :: Word32 -> ByteString
encodeWord32 = G.runPut . putWord32

encodeWord64 :: Word64 -> ByteString
encodeWord64 = G.runPut . G.putWord64be
