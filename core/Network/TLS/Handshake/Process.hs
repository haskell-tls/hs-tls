{-# LANGUAGE RecordWildCards #-}

-- |
-- process handshake message received
module Network.TLS.Handshake.Process (
    processHandshake,
    processHandshake13,
    startHandshake,
) where

import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Random
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.Imports
import Network.TLS.Packet
import Network.TLS.Sending
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types (MasterSecret (..), Role (..))

import Control.Concurrent.MVar
import Control.Monad.State.Strict (gets)

processHandshake :: Context -> Handshake -> IO ()
processHandshake ctx hs = do
    role <- usingState_ ctx getRole
    when (isHRR hs) $ usingHState ctx wrapAsMessageHash13
    void $ updateHandshake ctx False hs
    case hs of
        ClientKeyXchg content ->
            when (role == ServerRole) $
                processClientKeyXchg ctx content
        _ -> return ()
  where
    isHRR (ServerHello TLS12 srand _ _ _ _) = isHelloRetryRequest srand
    isHRR _ = False

processHandshake13 :: Context -> Handshake13 -> IO ()
processHandshake13 ctx = void . updateHandshake13 ctx

-- process the client key exchange message. the protocol expects the initial
-- client version received in ClientHello, not the negotiated version.
-- in case the version mismatch, generate a random master secret
processClientKeyXchg :: Context -> ClientKeyXchgAlgorithmData -> IO ()
processClientKeyXchg ctx (CKX_RSA encryptedPremaster) = do
    (rver, role, random) <- usingState_ ctx $ do
        (,,) <$> getVersion <*> getRole <*> genRandom 48
    ePremaster <- decryptRSA ctx encryptedPremaster
    masterSecret <- usingHState ctx $ do
        expectedVer <- gets hstClientVersion
        case ePremaster of
            Left _ -> setMasterSecretFromPre rver role random
            Right premaster -> case decodePreMasterSecret premaster of
                Left _ -> setMasterSecretFromPre rver role random
                Right (ver, _)
                    | ver /= expectedVer -> setMasterSecretFromPre rver role random
                    | otherwise -> setMasterSecretFromPre rver role premaster
    logKey ctx (MasterSecret masterSecret)
processClientKeyXchg ctx (CKX_DH clientDHValue) = do
    rver <- usingState_ ctx getVersion
    role <- usingState_ ctx getRole

    serverParams <- usingHState ctx getServerDHParams
    let params = serverDHParamsToParams serverParams
    unless (dhValid params $ dhUnwrapPublic clientDHValue) $
        throwCore $
            Error_Protocol "invalid client public key" IllegalParameter

    dhpriv <- usingHState ctx getDHPrivate
    let premaster = dhGetShared params dhpriv clientDHValue
    masterSecret <- usingHState ctx $ setMasterSecretFromPre rver role premaster
    logKey ctx (MasterSecret masterSecret)
processClientKeyXchg ctx (CKX_ECDH bytes) = do
    ServerECDHParams grp _ <- usingHState ctx getServerECDHParams
    case decodeGroupPublic grp bytes of
        Left _ ->
            throwCore $
                Error_Protocol "client public key cannot be decoded" IllegalParameter
        Right clipub -> do
            srvpri <- usingHState ctx getGroupPrivate
            case groupGetShared clipub srvpri of
                Just premaster -> do
                    rver <- usingState_ ctx getVersion
                    role <- usingState_ ctx getRole
                    masterSecret <- usingHState ctx $ setMasterSecretFromPre rver role premaster
                    logKey ctx (MasterSecret masterSecret)
                Nothing ->
                    throwCore $
                        Error_Protocol "cannot generate a shared secret on ECDH" IllegalParameter

-- initialize a new Handshake context (initial handshake or renegotiations)
startHandshake :: Context -> Version -> ClientRandom -> IO ()
startHandshake ctx ver crand =
    let hs = Just $ newEmptyHandshake ver crand
     in void $ swapMVar (ctxHandshake ctx) hs
