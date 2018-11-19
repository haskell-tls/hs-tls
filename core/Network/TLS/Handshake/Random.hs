-- |
-- Module      : Network.TLS.Handshake.Random
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.Random (
      serverRandom
    , clientRandom
    , hrrRandom
    , isHelloRetryRequest
    , isDowngraded
    ) where

import qualified Data.ByteString as B
import Network.TLS.Context.Internal
import Network.TLS.Struct

serverRandom :: Context -> Version -> [Version] -> IO ServerRandom
serverRandom ctx chosenVer suppVers
  | TLS13 `elem` suppVers = case chosenVer of
      TLS13  -> ServerRandom <$> getStateRNG ctx 32
      TLS12  -> ServerRandom <$> genServRand suffix12
      _      -> ServerRandom <$> genServRand suffix11
  | TLS12 `elem` suppVers = case chosenVer of
      TLS12  -> ServerRandom <$> getStateRNG ctx 32
      _      -> ServerRandom <$> genServRand suffix11
  | otherwise = ServerRandom <$> getStateRNG ctx 32
  where
    genServRand suff = do
        pref <- getStateRNG ctx 24
        return $ (pref `B.append` suff)

isDowngraded :: [Version] -> ServerRandom -> Bool
isDowngraded suppVers (ServerRandom sr)
  | TLS13 `elem` suppVers = suffix12 `B.isSuffixOf` sr
                         || suffix11 `B.isSuffixOf` sr
  | TLS12 `elem` suppVers = suffix11 `B.isSuffixOf` sr
  | otherwise             = False

suffix12 :: B.ByteString
suffix12 = B.pack [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01]

suffix11 :: B.ByteString
suffix11 = B.pack [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00]

-- ClientRandom in the second client hello for retry must be
-- the same as the first one.
clientRandom :: Context -> Maybe ClientRandom -> IO ClientRandom
clientRandom ctx Nothing   = ClientRandom <$> getStateRNG ctx 32
clientRandom _   (Just cr) = return cr

hrrRandom :: ServerRandom
hrrRandom = ServerRandom $ B.pack [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11
  , 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91
  , 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E
  , 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
  ]

isHelloRetryRequest :: ServerRandom -> Bool
isHelloRetryRequest = (== hrrRandom)
