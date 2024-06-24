{-# OPTIONS_GHC -Wno-orphans #-}

module Session (
    readClientSessionRef,
    clearClientSessionRef,
    twoSessionRefs,
    twoSessionManagers,
    setPairParamsSessionManagers,
    setPairParamsSessionResuming,
    oneSessionTicket,
) where

import Codec.Serialise
import Control.Monad
import qualified Data.ByteString.Lazy as L
import Data.IORef
import Network.TLS
import Network.TLS.Internal

----------------------------------------------------------------

readClientSessionRef :: (IORef (Maybe c), IORef (Maybe s)) -> IO (Maybe c)
readClientSessionRef refs = readIORef (fst refs)

clearClientSessionRef :: (IORef (Maybe c), IORef (Maybe s)) -> IO ()
clearClientSessionRef refs = writeIORef (fst refs) Nothing

twoSessionRefs :: IO (IORef (Maybe client), IORef (Maybe server))
twoSessionRefs = (,) <$> newIORef Nothing <*> newIORef Nothing

-- | simple session manager to store one session id and session data for a single thread.
-- a Real concurrent session manager would use an MVar and have multiples items.
oneSessionManager :: IORef (Maybe (SessionID, SessionData)) -> SessionManager
oneSessionManager ref =
    noSessionManager
        { sessionResume = \myId -> readIORef ref >>= maybeResume False myId
        , sessionResumeOnlyOnce = \myId -> readIORef ref >>= maybeResume True myId
        , sessionEstablish = \myId dat -> writeIORef ref (Just (myId, dat)) >> return Nothing
        , sessionInvalidate = \_ -> return ()
        , sessionUseTicket = False
        }
  where
    maybeResume onlyOnce myId (Just (sid, sdata))
        | sid == myId = when onlyOnce (writeIORef ref Nothing) >> return (Just sdata)
    maybeResume _ _ _ = return Nothing

twoSessionManagers
    :: (IORef (Maybe (SessionID, SessionData)), IORef (Maybe (SessionID, SessionData)))
    -> (SessionManager, SessionManager)
twoSessionManagers (cRef, sRef) = (oneSessionManager cRef, oneSessionManager sRef)

setPairParamsSessionManagers
    :: (SessionManager, SessionManager)
    -> (ClientParams, ServerParams)
    -> (ClientParams, ServerParams)
setPairParamsSessionManagers (clientManager, serverManager) (clientParams, serverParams) = (nc, ns)
  where
    nc =
        clientParams
            { clientShared = updateSessionManager clientManager $ clientShared clientParams
            }
    ns =
        serverParams
            { serverShared = updateSessionManager serverManager $ serverShared serverParams
            }
    updateSessionManager manager shared = shared{sharedSessionManager = manager}

----------------------------------------------------------------

setPairParamsSessionResuming
    :: (SessionID, SessionData)
    -> (ClientParams, ServerParams)
    -> (ClientParams, ServerParams)
setPairParamsSessionResuming sessionStuff (clientParams, serverParams) =
    ( clientParams{clientWantSessionResume = Just sessionStuff}
    , serverParams
    )

oneSessionTicket :: SessionManager
oneSessionTicket =
    noSessionManager
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
