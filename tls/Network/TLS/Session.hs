module Network.TLS.Session (
    SessionManager (..),
    noSessionManager,
    encodeSessionData,
    decodeSessionData,
) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

import Network.TLS.Crypto (Group (..))
import Network.TLS.Imports
import Network.TLS.Types
import Network.TLS.Wire

-- | A session manager.
-- In the server side, all fields are used.
-- In the client side, only 'sessionEstablish' is used.
data SessionManager = SessionManager
    { sessionResume :: SessionIDorTicket -> IO (Maybe SessionData)
    -- ^ Used on TLS 1.2\/1.3 servers to lookup 'SessionData' with 'SessionID' or to decrypt 'Ticket' to get 'SessionData'.
    -- It must not use up the session: it is also called first for 0RTT, before 'sessionResumeOnlyOnce'.
    , sessionResumeOnlyOnce :: SessionIDorTicket -> IO (Maybe SessionData)
    -- ^ Used for 0RTT on TLS 1.3 servers to lookup 'SessionData' with 'SessionID' or to decrypt 'Ticket' to get 'SessionData'.
    -- It is called after 'sessionResume' has found the session and the ClientHello has passed the freshness and binder checks.
    -- It is to return the 'SessionData' at most once for an identity, or early data can be replayed (RFC 9846 Section 8).
    -- With 'Nothing', the early data is refused but the session is resumed.
    , sessionEstablish :: SessionIDorTicket -> SessionData -> IO (Maybe Ticket)
    -- ^ Used on TLS 1.2\/1.3 servers to store 'SessionData' with 'SessionID' or to encrypt 'SessionData' to get 'Ticket' ignoring 'SessionID'. Used on TLS 1.2\/1.3 clients to store 'SessionData' with 'SessionIDorTicket' and then return 'Nothing'. For clients, only this field should be set with 'noSessionManager'.
    , sessionInvalidate :: SessionIDorTicket -> IO ()
    -- ^ Used on TLS 1.2 servers to delete 'SessionData' with 'SessionID' on errors.
    , sessionUseTicket :: Bool
    -- ^ Used on TLS 1.2 servers to decide to use 'SessionID' or 'Ticket'. Note that 'SessionID' and 'Ticket' are integrated as identity in TLS 1.3.
    }

-- | The session manager to do nothing.
noSessionManager :: SessionManager
noSessionManager =
    SessionManager
        { sessionResume = \_ -> return Nothing
        , sessionResumeOnlyOnce = \_ -> return Nothing
        , sessionEstablish = \_ _ -> return Nothing
        , sessionInvalidate = \_ -> return ()
        , -- Don't send NewSessionTicket in TLS 1.2 by default.
          -- Send NewSessionTicket with SessionID in TLS 1.3 by default.
          sessionUseTicket = False
        }

----------------------------------------------------------------

-- | Encode 'SessionData', e.g. to store it or to put it in a 'Ticket'.
-- The format starts with its own version and does not depend on the
-- Haskell types, so 'decodeSessionData' of a later release reads it or
-- returns 'Nothing'.
--
-- @since 2.7.0
encodeSessionData :: SessionData -> ByteString
encodeSessionData sd = runPut $ do
    putWord8 formatVersion
    let Version ver = sessionVersion sd
    putWord16 ver
    putWord16 $ sessionCipher sd
    putWord8 $ sessionCompression sd
    putMaybe (putOpaque16 . BC.pack) $ sessionClientSNI sd
    putOpaque16 $ sessionSecret sd
    putMaybe (\(Group g) -> putWord16 g) $ sessionGroup sd
    putMaybe putTicketInfo $ sessionTicketInfo sd
    putMaybe putOpaque16 $ sessionALPN sd
    putWord32 $ sessionMaxEarlyDataSize sd
    putOpaque8 $ B.pack $ map flagToWord8 $ sessionFlags sd
    putMaybe putOpaque32 $ sessionClientCertificate sd
    putMaybe putOpaque32 $ sessionAppData sd
  where
    putTicketInfo ti = do
        putWord32 $ lifetime ti
        putWord32 $ ageAdd ti
        putWord64 $ txrxTime ti
        putMaybe putWord64 $ estimatedRTT ti

-- | Decode what 'encodeSessionData' made.  'Nothing' for anything else,
-- including the format of another release which this one cannot read.
--
-- @since 2.7.0
decodeSessionData :: ByteString -> Maybe SessionData
decodeSessionData = runGetMaybe $ do
    fv <- getWord8
    when (fv /= formatVersion) $ fail "unknown format"
    ver <- Version <$> getWord16
    cipher <- getWord16
    compression <- getWord8
    sni <- getMaybe (BC.unpack <$> getOpaque16)
    secret <- getOpaque16
    grp <- getMaybe (Group <$> getWord16)
    tinfo <- getMaybe getTicketInfo
    alpn <- getMaybe getOpaque16
    maxEarly <- getWord32
    flags <- mapMaybe word8ToFlag . B.unpack <$> getOpaque8
    cert <- getMaybe getOpaque32
    appData <- getMaybe getOpaque32
    return
        SessionData
            { sessionVersion = ver
            , sessionCipher = cipher
            , sessionCompression = compression
            , sessionClientSNI = sni
            , sessionSecret = secret
            , sessionGroup = grp
            , sessionTicketInfo = tinfo
            , sessionALPN = alpn
            , sessionMaxEarlyDataSize = maxEarly
            , sessionFlags = flags
            , sessionClientCertificate = cert
            , sessionAppData = appData
            }
  where
    getTicketInfo =
        TLS13TicketInfo
            <$> getWord32
            <*> getWord32
            <*> getWord64
            <*> getMaybe getWord64

-- Bumped whenever the format changes.
formatVersion :: Word8
formatVersion = 1

-- Numbers fixed here rather than by Enum, so that the format does not
-- change with the order of the constructors.  Unknown ones are skipped.
flagToWord8 :: SessionFlag -> Word8
flagToWord8 SessionEMS = 0

word8ToFlag :: Word8 -> Maybe SessionFlag
word8ToFlag 0 = Just SessionEMS
word8ToFlag _ = Nothing

putMaybe :: (a -> Put) -> Maybe a -> Put
putMaybe _ Nothing = putWord8 0
putMaybe p (Just x) = putWord8 1 >> p x

getMaybe :: Get a -> Get (Maybe a)
getMaybe g = do
    tag <- getWord8
    case tag of
        0 -> return Nothing
        1 -> Just <$> g
        _ -> fail "bad Maybe tag"

putOpaque32 :: ByteString -> Put
putOpaque32 b = putWord32 (fromIntegral $ B.length b) >> putBytes b

getOpaque32 :: Get ByteString
getOpaque32 = do
    len <- getWord32
    -- Refuse a length beyond the input before allocating for it.
    r <- remaining
    when (fromIntegral len > r) $ fail "too short"
    getBytes $ fromIntegral len
