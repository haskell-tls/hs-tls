{-# OPTIONS_GHC -Wno-orphans #-}

module Network.TLS.SessionTicket (
    newSesssionTicketManager,
) where

import Codec.Serialise
import qualified Data.ByteString.Lazy as L
import Network.TLS
import Network.TLS.Internal

newSesssionTicketManager :: IO SessionManager
newSesssionTicketManager = return sessionTicketManager

sessionTicketManager :: SessionManager
sessionTicketManager =
    SessionManager
        { sessionResume = resume
        , sessionResumeOnlyOnce = resume
        , sessionEstablish = \_ dat -> return $ Just $ L.toStrict $ serialise dat
        , sessionInvalidate = \_ -> return ()
        , sessionUseTicket = True
        }

resume :: Ticket -> IO (Maybe SessionData)
resume ticket
    | isTicket ticket = return $ Just $ deserialise $ L.fromStrict ticket
    | otherwise = return Nothing

instance Serialise Group
instance Serialise Version
instance Serialise TLS13TicketInfo
instance Serialise SessionFlag
instance Serialise SessionData
