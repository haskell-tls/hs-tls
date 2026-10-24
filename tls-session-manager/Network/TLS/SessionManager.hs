-- | In-memory TLS 1.2/1.3 session manager.
--
-- * Limitation: you can set the maximum size of the session data database.
-- * Automatic pruning: old session data over their lifetime are pruned automatically.
-- * Energy saving: no dedicate pruning thread is running when the size of session data database is zero.
-- * Replay resistance: for 0-RTT early data of TLS 1.3, each session data is used at most once ('sessionResumeOnlyOnce').  Other resumptions may use it again.
module Network.TLS.SessionManager (
    newSessionManager,
    Config,
    defaultConfig,
    ticketLifetime,
    pruningDelay,
    dbMaxSize,
) where

import Network.TLS.SessionManager.Internal
