{-# LANGUAGE PatternGuards #-}

module Network.TLS.Handshake.Random (
    serverRandom,
    clientRandom,
    isDowngraded,
) where

import qualified Data.ByteString as B
import Network.TLS.Context.Internal
import Network.TLS.Struct

-- | Generate a server random suitable for the version selected by the server
-- and its supported versions.  We use an 8-byte downgrade suffix when the
-- selected version is lowered because of incomplete client support, but also
-- when a version downgrade has been forced with 'debugVersionForced'.  This
-- second part allows to test that the client implementation correctly detects
-- downgrades.  The suffix is not used when forcing TLS13 to a server not
-- officially supporting TLS13 (this is not a downgrade scenario but only the
-- consequence of our debug API allowing this).
serverRandom :: Context -> Version -> [Version] -> IO ServerRandom
serverRandom ctx chosenVer suppVers
    | TLS13 `elem` suppVers = case chosenVer of
        TLS13 -> ServerRandom <$> getStateRNG ctx 32
        TLS12 -> ServerRandom <$> genServRand suffix12
        _ -> ServerRandom <$> genServRand suffix11
    | TLS12 `elem` suppVers = case chosenVer of
        TLS13 -> ServerRandom <$> getStateRNG ctx 32
        TLS12 -> ServerRandom <$> getStateRNG ctx 32
        _ -> ServerRandom <$> genServRand suffix11
    | otherwise = ServerRandom <$> getStateRNG ctx 32
  where
    genServRand suff = do
        pref <- getStateRNG ctx 24
        return (pref `B.append` suff)

-- | Test if the negotiated version was artificially downgraded (that is, for
-- other reason than the versions supported by the client).
isDowngraded :: Version -> [Version] -> ServerRandom -> Bool
isDowngraded ver suppVers (ServerRandom sr)
    | ver <= TLS12
    , TLS13 `elem` suppVers =
        suffix12 `B.isSuffixOf` sr
            || suffix11 `B.isSuffixOf` sr
    | ver <= TLS11
    , TLS12 `elem` suppVers =
        suffix11 `B.isSuffixOf` sr
    | otherwise = False

suffix12 :: B.ByteString
suffix12 = B.pack [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01]

suffix11 :: B.ByteString
suffix11 = B.pack [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00]

clientRandom :: Context -> IO ClientRandom
clientRandom ctx = ClientRandom <$> getStateRNG ctx 32
