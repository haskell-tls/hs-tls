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
    ) where

import Data.ByteString (ByteString)

import Control.Monad.Error
import Control.Monad.State (gets)

import Network.TLS.Types (Role(..), invertRole)
import Network.TLS.Util
import Network.TLS.Packet
import Network.TLS.Struct
import Network.TLS.State
import Network.TLS.Context
import Network.TLS.Handshake.State
import Network.TLS.Handshake.Key
import Network.TLS.Extension
import Data.X509

processHandshake :: MonadIO m => Context -> Handshake -> m ()
processHandshake ctx hs = do
    role <- usingState_ ctx isClientContext
    case hs of
        ClientHello cver ran _ _ _ ex _ -> when (role == ServerRole) $ do
            mapM_ (usingState_ ctx . processClientExtension) ex
            usingState_ ctx $ startHandshakeClient cver ran
        Certificates certs            -> usingState_ ctx $ processCertificates role certs
        ClientKeyXchg content         -> when (role == ServerRole) $ do
            usingState_ ctx $ processClientKeyXchg content
        HsNextProtocolNegotiation selected_protocol ->
            when (role == ServerRole) $ usingState_ ctx $ setNegotiatedProtocol selected_protocol
        Finished fdata                -> usingState_ ctx $ processClientFinished fdata
        _                             -> return ()
    let encoded = encodeHandshake hs
    when (certVerifyHandshakeMaterial hs) $ usingHState ctx $ addHandshakeMessage encoded
    when (finishHandshakeTypeMaterial $ typeOfHandshake hs) $ usingHState ctx $ updateHandshakeDigest encoded
  where -- secure renegotiation
        processClientExtension (0xff01, content) = do
            v <- getVerifiedData ClientRole
            let bs = extensionEncode (SecureRenegotiation v Nothing)
            unless (bs `bytesEq` content) $ throwError $ Error_Protocol ("client verified data not matching: " ++ show v ++ ":" ++ show content, True, HandshakeFailure)

            setSecureRenegotiation True
        -- unknown extensions
        processClientExtension _ = return ()

        processCertificates :: Role -> CertificateChain -> TLSSt ()
        processCertificates ServerRole (CertificateChain []) = return ()
        processCertificates ClientRole (CertificateChain []) =
            throwError $ Error_Protocol ("server certificate missing", True, HandshakeFailure)
        processCertificates role (CertificateChain (c:_))
            | role == ClientRole = withHandshakeM $ setPublicKey pubkey
            | otherwise          = withHandshakeM $ setClientPublicKey pubkey
          where pubkey = certPubKey $ getCertificate c

-- process the client key exchange message. the protocol expects the initial
-- client version received in ClientHello, not the negotiated version.
-- in case the version mismatch, generate a random master secret
processClientKeyXchg :: ByteString -> TLSSt ()
processClientKeyXchg encryptedPremaster = do
    rver        <- getVersion
    role        <- isClientContext
    random      <- genRandom 48
    ePremaster  <- decryptRSA encryptedPremaster
    withHandshakeM $ do
        expectedVer <- gets hstClientVersion
        case ePremaster of
            Left _          -> setMasterSecretFromPre rver role random
            Right premaster -> case decodePreMasterSecret premaster of
                Left _                   -> setMasterSecretFromPre rver role random
                Right (ver, _)
                    | ver /= expectedVer -> setMasterSecretFromPre rver role random
                    | otherwise          -> setMasterSecretFromPre rver role premaster

processClientFinished :: FinishedData -> TLSSt ()
processClientFinished fdata = do
    cc       <- isClientContext
    ver      <- getVersion
    expected <- withHandshakeM $ getHandshakeDigest ver $ invertRole cc
    when (expected /= fdata) $ do
        throwError $ Error_Protocol("bad record mac", True, BadRecordMac)
    updateVerifiedData ServerRole fdata
    return ()

