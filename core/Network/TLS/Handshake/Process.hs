-- |
-- Module      : Network.TLS.Handshake.Process
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- process handshake message received
--
module Network.TLS.Handshake.Process
    ( processHandshake
    , processHandshake13
    , startHandshake
    , getHandshakeDigest
    ) where

import Control.Concurrent.MVar
import Control.Monad.State.Strict (gets)
import Control.Monad.IO.Class (liftIO)

import Network.TLS.Types (Role(..), invertRole, TrafficSecret(..))
import Network.TLS.Util
import Network.TLS.Packet
import Network.TLS.ErrT
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.State
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Imports
import Network.TLS.Handshake.Random
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.Handshake.Key
import Network.TLS.Extension
import Network.TLS.Parameters
import Network.TLS.Sending13
import Data.X509 (CertificateChain(..), Certificate(..), getCertificate)

processHandshake :: Context -> Handshake -> IO ()
processHandshake ctx hs = do
    role <- usingState_ ctx isClientContext
    case hs of
        ClientHello cver ran _ cids _ ex _ -> when (role == ServerRole) $ do
            mapM_ (usingState_ ctx . processClientExtension) ex
            -- RFC 5746: secure renegotiation
            -- TLS_EMPTY_RENEGOTIATION_INFO_SCSV: {0x00, 0xFF}
            when (secureRenegotiation && (0xff `elem` cids)) $
                usingState_ ctx $ setSecureRenegotiation True
            hrr <- usingState_ ctx getTLS13HRR
            unless hrr $ startHandshake ctx cver ran
        Certificates certs            -> processCertificates role certs
        ClientKeyXchg content         -> when (role == ServerRole) $ do
            processClientKeyXchg ctx content
        Finished fdata                -> processClientFinished ctx fdata
        _                             -> return ()
    let encoded = encodeHandshake hs
    when (isHRR hs) $ usingHState ctx wrapAsMessageHash13
    when (certVerifyHandshakeMaterial hs) $ usingHState ctx $ addHandshakeMessage encoded
    when (finishHandshakeTypeMaterial $ typeOfHandshake hs) $ usingHState ctx $ updateHandshakeDigest encoded
  where secureRenegotiation = supportedSecureRenegotiation $ ctxSupported ctx
        -- RFC5746: secure renegotiation
        -- the renegotiation_info extension: 0xff01
        processClientExtension (ExtensionRaw 0xff01 content) | secureRenegotiation = do
            v <- getVerifiedData ClientRole
            let bs = extensionEncode (SecureRenegotiation v Nothing)
            unless (bs `bytesEq` content) $ throwError $ Error_Protocol ("client verified data not matching: " ++ show v ++ ":" ++ show content, True, HandshakeFailure)

            setSecureRenegotiation True
        -- unknown extensions
        processClientExtension _ = return ()

        processCertificates :: Role -> CertificateChain -> IO ()
        processCertificates ServerRole (CertificateChain []) = return ()
        processCertificates ClientRole (CertificateChain []) =
            throwCore $ Error_Protocol ("server certificate missing", True, HandshakeFailure)
        processCertificates _ (CertificateChain (c:_)) =
            usingHState ctx $ setPublicKey pubkey
          where pubkey = certPubKey $ getCertificate c

        isHRR (ServerHello TLS12 srand _ _ _ _) = isHelloRetryRequest srand
        isHRR _                                 = False

processHandshake13 :: Context -> Handshake13 -> IO ()
processHandshake13 = updateHandshake13

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
            Left _          -> setMasterSecretFromPre rver role random
            Right premaster -> case decodePreMasterSecret premaster of
                Left _                   -> setMasterSecretFromPre rver role random
                Right (ver, _)
                    | ver /= expectedVer -> setMasterSecretFromPre rver role random
                    | otherwise          -> setMasterSecretFromPre rver role premaster
    liftIO $ logKey ctx (MasterSecret12 masterSecret)

processClientKeyXchg ctx (CKX_DH clientDHValue) = do
    rver <- usingState_ ctx getVersion
    role <- usingState_ ctx isClientContext

    serverParams <- usingHState ctx getServerDHParams
    let params = serverDHParamsToParams serverParams
    unless (dhValid params $ dhUnwrapPublic clientDHValue) $
        throwCore $ Error_Protocol ("invalid client public key", True, IllegalParameter)

    dhpriv       <- usingHState ctx getDHPrivate
    let premaster = dhGetShared params dhpriv clientDHValue
    masterSecret <- usingHState ctx $ setMasterSecretFromPre rver role premaster
    liftIO $ logKey ctx (MasterSecret12 masterSecret)

processClientKeyXchg ctx (CKX_ECDH bytes) = do
    ServerECDHParams grp _ <- usingHState ctx getServerECDHParams
    case decodeGroupPublic grp bytes of
      Left _ -> throwCore $ Error_Protocol ("client public key cannot be decoded", True, IllegalParameter)
      Right clipub -> do
          srvpri <- usingHState ctx getGroupPrivate
          case groupGetShared clipub srvpri of
              Just premaster -> do
                  rver <- usingState_ ctx getVersion
                  role <- usingState_ ctx isClientContext
                  masterSecret <- usingHState ctx $ setMasterSecretFromPre rver role premaster
                  liftIO $ logKey ctx (MasterSecret12 masterSecret)
              Nothing -> throwCore $ Error_Protocol ("cannot generate a shared secret on ECDH", True, IllegalParameter)

processClientFinished :: Context -> FinishedData -> IO ()
processClientFinished ctx fdata = do
    (cc,ver) <- usingState_ ctx $ (,) <$> isClientContext <*> getVersion
    expected <- usingHState ctx $ getHandshakeDigest ver $ invertRole cc
    when (expected /= fdata) $ decryptError "cannot verify finished"
    usingState_ ctx $ updateVerifiedData ServerRole fdata
    return ()

-- initialize a new Handshake context (initial handshake or renegotiations)
startHandshake :: Context -> Version -> ClientRandom -> IO ()
startHandshake ctx ver crand =
    let hs = Just $ newEmptyHandshake ver crand
    in liftIO $ void $ swapMVar (ctxHandshake ctx) hs
