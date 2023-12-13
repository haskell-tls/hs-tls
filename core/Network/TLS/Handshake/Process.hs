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
import Network.TLS.ErrT
import Network.TLS.Extension
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Random
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.Imports
import Network.TLS.Packet
import Network.TLS.Parameters
import Network.TLS.Sending
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types (MasterSecret (..), Role (..), invertRole)
import Network.TLS.Util

import Control.Concurrent.MVar
import Control.Monad.State.Strict (gets)
import Data.IORef (writeIORef)
import Data.X509 (Certificate (..), CertificateChain (..), getCertificate)

processHandshake :: Context -> Handshake -> IO ()
processHandshake ctx hs = do
    role <- usingState_ ctx isClientContext
    case hs of
        ClientHello cver ran _ CH{..} -> when (role == ServerRole) $ do
            mapM_ (usingState_ ctx . processClientExtension) chExtensions
            -- RFC 5746: secure renegotiation
            -- TLS_EMPTY_RENEGOTIATION_INFO_SCSV: {0x00, 0xFF}
            when (secureRenegotiation && (0xff `elem` chCiphers)) $
                usingState_ ctx $
                    setSecureRenegotiation True
            hrr <- usingState_ ctx getTLS13HRR
            unless hrr $ startHandshake ctx cver ran
        Certificates certs -> processCertificates role certs
        Finished fdata -> processClientFinished ctx fdata
        _ -> return ()
    when (isHRR hs) $ usingHState ctx wrapAsMessageHash13
    void $ updateHandshake ctx ServerRole hs
    case hs of
        ClientKeyXchg content ->
            when (role == ServerRole) $
                processClientKeyXchg ctx content
        _ -> return ()
  where
    secureRenegotiation = supportedSecureRenegotiation $ ctxSupported ctx
    -- RFC5746: secure renegotiation
    processClientExtension (ExtensionRaw EID_SecureRenegotiation content) | secureRenegotiation = do
        v <- getVerifiedData ClientRole
        let bs = extensionEncode (SecureRenegotiation v Nothing)
        unless (bs `bytesEq` content) $
            throwError $
                Error_Protocol
                    ("client verified data not matching: " ++ show v ++ ":" ++ show content)
                    HandshakeFailure

        setSecureRenegotiation True
    -- unknown extensions
    processClientExtension _ = return ()

    processCertificates :: Role -> CertificateChain -> IO ()
    processCertificates ServerRole (CertificateChain []) = return ()
    processCertificates ClientRole (CertificateChain []) =
        throwCore $ Error_Protocol "server certificate missing" HandshakeFailure
    processCertificates _ (CertificateChain (c : _)) =
        usingHState ctx $ setPublicKey pubkey
      where
        pubkey = certPubKey $ getCertificate c

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
        (,,) <$> getVersion <*> isClientContext <*> genRandom 48
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
    role <- usingState_ ctx isClientContext

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
                    role <- usingState_ ctx isClientContext
                    masterSecret <- usingHState ctx $ setMasterSecretFromPre rver role premaster
                    logKey ctx (MasterSecret masterSecret)
                Nothing ->
                    throwCore $
                        Error_Protocol "cannot generate a shared secret on ECDH" IllegalParameter

processClientFinished :: Context -> FinishedData -> IO ()
processClientFinished ctx fdata = do
    (cc, ver) <- usingState_ ctx $ (,) <$> isClientContext <*> getVersion
    expected <- usingHState ctx $ getHandshakeDigest ver $ invertRole cc
    when (expected /= fdata) $ decryptError "cannot verify finished"
    writeIORef (ctxPeerFinished ctx) $ Just fdata

-- initialize a new Handshake context (initial handshake or renegotiations)
startHandshake :: Context -> Version -> ClientRandom -> IO ()
startHandshake ctx ver crand =
    let hs = Just $ newEmptyHandshake ver crand
     in void $ swapMVar (ctxHandshake ctx) hs
