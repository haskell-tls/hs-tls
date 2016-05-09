-- |
-- Module      : Network.TLS.Wire
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Wire module is a specialized marshalling/unmarshalling package related to the TLS protocol.
-- all multibytes values are written as big endian.
--
{-# LANGUAGE CPP #-}
module Network.TLS.Wire
    ( Get
    , GetResult(..)
    , GetContinuation
    , runGet
    , runGetErr
    , runGetMaybe
    , tryGet
    , remaining
    , getWord8
    , getWords8
    , getWord16
    , getWords16
    , getWord24
    , getBytes
    , getOpaque8
    , getOpaque16
    , getOpaque24
    , getInteger16
    , getBigNum16
    , getList
    , processBytes
    , isEmpty
    , Put
    , runPut
    , putWord8
    , putWords8
    , putWord16
    , putWords16
    , putWord24
    , putBytes
    , putOpaque8
    , putOpaque16
    , putOpaque24
    , putInteger16
    , putBigNum16
    , encodeWord16
    , encodeWord32
    , encodeWord64
    ) where

import Data.Serialize.Get hiding (runGet)
import qualified Data.Serialize.Get as G
import Data.Serialize.Put
#if __GLASGOW_HASKELL__ < 710
import Control.Applicative ((<$>))
#endif
import Control.Monad
import qualified Data.ByteString as B
import Data.Word
import Data.Bits
import Network.TLS.Struct
import Network.TLS.Util.Serialization

type GetContinuation a = Bytes -> GetResult a
data GetResult a =
      GotError TLSError
    | GotPartial (GetContinuation a)
    | GotSuccess a
    | GotSuccessRemaining a Bytes

runGet :: String -> Get a -> Bytes -> GetResult a
runGet lbl f = toGetResult <$> G.runGetPartial (label lbl f)
  where toGetResult (G.Fail err _)    = GotError (Error_Packet_Parsing err)
        toGetResult (G.Partial cont)  = GotPartial (toGetResult <$> cont)
        toGetResult (G.Done r bsLeft)
            | B.null bsLeft = GotSuccess r
            | otherwise     = GotSuccessRemaining r bsLeft

runGetErr :: String -> Get a -> Bytes -> Either TLSError a
runGetErr lbl getter b = toSimple $ runGet lbl getter b
  where toSimple (GotError err) = Left err
        toSimple (GotPartial _) = Left (Error_Packet_Parsing (lbl ++ ": parsing error: partial packet"))
        toSimple (GotSuccessRemaining _ _) = Left (Error_Packet_Parsing (lbl ++ ": parsing error: remaining bytes"))
        toSimple (GotSuccess r) = Right r

runGetMaybe :: Get a -> Bytes -> Maybe a
runGetMaybe f = either (const Nothing) Just . G.runGet f

tryGet :: Get a -> Bytes -> Maybe a
tryGet f = either (const Nothing) Just . G.runGet f

getWords8 :: Get [Word8]
getWords8 = getWord8 >>= \lenb -> replicateM (fromIntegral lenb) getWord8

getWord16 :: Get Word16
getWord16 = getWord16be

getWords16 :: Get [Word16]
getWords16 = getWord16 >>= \lenb -> replicateM (fromIntegral lenb `div` 2) getWord16

getWord24 :: Get Int
getWord24 = do
    a <- fromIntegral <$> getWord8
    b <- fromIntegral <$> getWord8
    c <- fromIntegral <$> getWord8
    return $ (a `shiftL` 16) .|. (b `shiftL` 8) .|. c

getOpaque8 :: Get Bytes
getOpaque8 = getWord8 >>= getBytes . fromIntegral

getOpaque16 :: Get Bytes
getOpaque16 = getWord16 >>= getBytes . fromIntegral

getOpaque24 :: Get Bytes
getOpaque24 = getWord24 >>= getBytes

getInteger16 :: Get Integer
getInteger16 = os2ip <$> getOpaque16

getBigNum16 :: Get BigNum
getBigNum16 = BigNum <$> getOpaque16

getList :: Int -> (Get (Int, a)) -> Get [a]
getList totalLen getElement = isolate totalLen (getElements totalLen)
  where getElements len
            | len < 0     = error "list consumed too much data. should never happen with isolate."
            | len == 0    = return []
            | otherwise   = getElement >>= \(elementLen, a) -> liftM ((:) a) (getElements (len - elementLen))

processBytes :: Int -> Get a -> Get a
processBytes i f = isolate i f

putWords8 :: [Word8] -> Put
putWords8 l = do
    putWord8 $ fromIntegral (length l)
    mapM_ putWord8 l

putWord16 :: Word16 -> Put
putWord16 = putWord16be

putWord32 :: Word32 -> Put
putWord32 = putWord32be

putWords16 :: [Word16] -> Put
putWords16 l = do
    putWord16 $ 2 * (fromIntegral $ length l)
    mapM_ putWord16 l

putWord24 :: Int -> Put
putWord24 i = do
    let a = fromIntegral ((i `shiftR` 16) .&. 0xff)
    let b = fromIntegral ((i `shiftR` 8) .&. 0xff)
    let c = fromIntegral (i .&. 0xff)
    mapM_ putWord8 [a,b,c]

putBytes :: Bytes -> Put
putBytes = putByteString

putOpaque8 :: Bytes -> Put
putOpaque8 b = putWord8 (fromIntegral $ B.length b) >> putBytes b

putOpaque16 :: Bytes -> Put
putOpaque16 b = putWord16 (fromIntegral $ B.length b) >> putBytes b

putOpaque24 :: Bytes -> Put
putOpaque24 b = putWord24 (B.length b) >> putBytes b

putInteger16 :: Integer -> Put
putInteger16 = putOpaque16 . i2osp

putBigNum16 :: BigNum -> Put
putBigNum16 (BigNum b) = putOpaque16 b

encodeWord16 :: Word16 -> Bytes
encodeWord16 = runPut . putWord16

encodeWord32 :: Word32 -> Bytes
encodeWord32 = runPut . putWord32

encodeWord64 :: Word64 -> Bytes
encodeWord64 = runPut . putWord64be
