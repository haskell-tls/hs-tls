module Network.TLS.Context.Window(HasSequenceNumber(..),maybeCacheMaybeGetNext, Window,newWindow)  where

import Data.Word
import Data.IORef
import Data.Bits

class HasSequenceNumber a where
  getSequenceNumber :: a -> Word64


data (HasSequenceNumber a) => Window a = Window
                                         !Word64 -- sequence number of a next expected record
                                         !Word64 -- bitmask of cached records
                                         ![(Word64, a)] -- the cache itself
                                         deriving(Show)

-- Extract a record from cache, if there's a record with expected sequence number
maybeGetNext :: (HasSequenceNumber a) => Window a -> (Window a, Maybe a)
maybeGetNext window@(Window next mask cache) =
  if 0 /= mask .&. 1
  then let next' = next + 1
           mask' = mask `shiftR` 1
           mrecord = lookup next cache -- this should always be Just _ but here we can avoid checking it
           cache' = filter ((>= next') . fst) cache
       in (Window next' mask' cache', mrecord)
  else (window, Nothing)

-- Add a record to the cache.
-- If this cannot be done within current window, then
--   - either "shift" it by exactly the number if missing records,
--     if there's not too many of them missing to catch up with the new record,
--   - or, if that won't help (i.e. the new arrived record with way too different
--     sequence number) - then reset the window
--     and make the new record the next expected one.
cacheRecord :: (HasSequenceNumber a) => a -> Window a -> Window a
cacheRecord record window@(Window next mask cache) =
  let sn = getSequenceNumber record
      nbit = fromIntegral $ sn - next
  in if nbit < 0
     then window
     else if nbit < 64
          then let mask' = mask .|. (1 `shiftL` nbit)
                   cache' = ((sn, record) : cache)
               in if mask /= mask'
                  then Window next mask' cache'
                  else window
          else let nmissing = ctz mask
                   nbit' = nbit - nmissing
               in if nbit' < 64
                  then let mask' = (mask `shiftR` nmissing) .|. (1 `shiftL` nbit')
                           next' = next + (fromIntegral $ nmissing)
                           cache' = ((sn, record) : cache)
                       in Window next' mask' cache'
                  else Window sn 1 [(sn, record)]

-- Count Trailing Zeros. (for instance, ctz 0b00101000 == 3)
-- There's for sure some clever trick to do it
-- (that I don't care of so I'll just slightly unroll the loop)
ctz :: Word64 -> Int
ctz 0 = 64
ctz x | x .&. 1 /= 0 = 0
      | x .&. 2 /= 0 = 1
      | x .&. 4 /= 0 = 2
      | x .&. 8 /= 0 = 3
      | otherwise = 4 + ctz (x `shiftR` 4)

maybeCacheMaybeGetNext :: (HasSequenceNumber a) => IORef (Window a) -> Maybe a -> IO (Maybe a)
maybeCacheMaybeGetNext ctx Nothing = atomicModifyIORef' ctx maybeGetNext
maybeCacheMaybeGetNext ctx (Just record) = atomicModifyIORef' ctx $ maybeGetNext . cacheRecord record

newWindow :: (HasSequenceNumber a) => Window a
newWindow = Window 0 0 []

{-
instance HasSequenceNumber Word64 where
  getSequenceNumber = id

test = do
  w <- newIORef newWindow
  let s :: Maybe Word64 -> IO ()
      s = putStrLn . show
      x = [Just 0,Just 1,Just 2,Just 0,Just 5,Just 4,Nothing,Just 3,Nothing,Nothing,Nothing,Just 3,Just 6]
  mapM (maybeCacheMaybeGetNext w) x >>= mapM_ s
  readIORef w >>= putStrLn . show
-}

