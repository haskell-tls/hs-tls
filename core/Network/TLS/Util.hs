{-# LANGUAGE ScopedTypeVariables #-}
module Network.TLS.Util
        ( sub
        , takelast
        , partition3
        , partition6
        , fromJust
        , and'
        , (&&!)
        , bytesEq
        , fmapEither
        , catchException
        ) where

import qualified Data.ByteString as B
import Network.TLS.Imports

import Control.Exception (SomeException)
import Control.Concurrent.Async

sub :: ByteString -> Int -> Int -> Maybe ByteString
sub b offset len
    | B.length b < offset + len = Nothing
    | otherwise                 = Just $ B.take len $ snd $ B.splitAt offset b

takelast :: Int -> ByteString -> Maybe ByteString
takelast i b
    | B.length b >= i = sub b (B.length b - i) i
    | otherwise       = Nothing

partition3 :: ByteString -> (Int,Int,Int) -> Maybe (ByteString, ByteString, ByteString)
partition3 bytes (d1,d2,d3)
    | any (< 0) l             = Nothing
    | sum l /= B.length bytes = Nothing
    | otherwise               = Just (p1,p2,p3)
        where l        = [d1,d2,d3]
              (p1, r1) = B.splitAt d1 bytes
              (p2, r2) = B.splitAt d2 r1
              (p3, _)  = B.splitAt d3 r2

partition6 :: ByteString -> (Int,Int,Int,Int,Int,Int) -> Maybe (ByteString, ByteString, ByteString, ByteString, ByteString, ByteString)
partition6 bytes (d1,d2,d3,d4,d5,d6) = if B.length bytes < s then Nothing else Just (p1,p2,p3,p4,p5,p6)
  where s        = sum [d1,d2,d3,d4,d5,d6]
        (p1, r1) = B.splitAt d1 bytes
        (p2, r2) = B.splitAt d2 r1
        (p3, r3) = B.splitAt d3 r2
        (p4, r4) = B.splitAt d4 r3
        (p5, r5) = B.splitAt d5 r4
        (p6, _)  = B.splitAt d6 r5

fromJust :: String -> Maybe a -> a
fromJust what Nothing  = error ("fromJust " ++ what ++ ": Nothing") -- yuck
fromJust _    (Just x) = x

-- | This is a strict version of and
and' :: [Bool] -> Bool
and' l = foldl' (&&!) True l

-- | This is a strict version of &&.
(&&!) :: Bool -> Bool -> Bool
True  &&! True  = True
True  &&! False = False
False &&! True  = False
False &&! False = False

-- | verify that 2 bytestrings are equals.
-- it's a non lazy version, that will compare every bytes.
-- arguments with different length will bail out early
bytesEq :: ByteString -> ByteString -> Bool
bytesEq b1 b2
    | B.length b1 /= B.length b2 = False
    | otherwise                  = and' $ B.zipWith (==) b1 b2

fmapEither :: (a -> b) -> Either l a -> Either l b
fmapEither f = fmap f

catchException :: IO a -> (SomeException -> IO a) -> IO a
catchException action handler = withAsync action waitCatch >>= either handler return
