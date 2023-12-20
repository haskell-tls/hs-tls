{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Network.TLS.Handshake.Client
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
module Network.TLS.Handshake.Client.TLS13 (
    recvServerSecondFlight13,
    sendClientSecondFlight13,
    postHandshakeAuthClientWith,
) where

import Control.Exception (bracket)
import Control.Monad.State.Strict
import qualified Data.ByteString as B

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Client.Common
import Network.TLS.Handshake.Common hiding (expectFinished)
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Control
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.Parameters
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types
import Network.TLS.X509

----------------------------------------------------------------

type Pass =
    ( CipherChoice
    , BaseSecret HandshakeSecret
    , ClientTrafficSecret HandshakeSecret
    , Bool
    , [ExtensionRaw]
    )

recvServerSecondFlight13 :: ClientParams -> Context -> Maybe Group -> IO Pass
recvServerSecondFlight13 cparams ctx groupSent = do
    choice <- makeCipherChoice TLS13 <$> usingHState ctx getPendingCipher
    recvServerSecondFlight13' cparams ctx groupSent choice

recvServerSecondFlight13'
    :: ClientParams
    -> Context
    -> Maybe Group
    -> CipherChoice
    -> IO
        ( CipherChoice
        , BaseSecret HandshakeSecret
        , ClientTrafficSecret HandshakeSecret
        , Bool
        , [ExtensionRaw]
        )
recvServerSecondFlight13' cparams ctx groupSent choice = do
    (_, hkey, resuming) <- switchToHandshakeSecret
    let handshakeSecret = triBase hkey
        clientHandshakeSecret = triClient hkey
        serverHandshakeSecret = triServer hkey
        handSecInfo = HandshakeSecretInfo usedCipher (clientHandshakeSecret, serverHandshakeSecret)
    contextSync ctx $ RecvServerHello handSecInfo
    (rtt0accepted, eexts) <- runRecvHandshake13 $ do
        accext <- recvHandshake13 ctx expectEncryptedExtensions
        unless resuming $ recvHandshake13 ctx expectCertRequest
        recvHandshake13hash ctx $ expectFinished serverHandshakeSecret
        return accext
    return (choice, handshakeSecret, clientHandshakeSecret, rtt0accepted, eexts)
  where
    usedCipher = cCipher choice
    usedHash = cHash choice

    hashSize = hashDigestSize usedHash

    switchToHandshakeSecret = do
        ensureRecvComplete ctx
        ecdhe <- calcSharedKey
        (earlySecret, resuming) <- makeEarlySecret
        handKey <- calculateHandshakeSecret ctx choice earlySecret ecdhe
        let serverHandshakeSecret = triServer handKey
        setRxState ctx usedHash usedCipher serverHandshakeSecret
        return (usedCipher, handKey, resuming)

    calcSharedKey = do
        serverKeyShare <- do
            mks <- usingState_ ctx getTLS13KeyShare
            case mks of
                Just (KeyShareServerHello ks) -> return ks
                Just _ ->
                    throwCore $ Error_Protocol "invalid key_share value" IllegalParameter
                Nothing ->
                    throwCore $
                        Error_Protocol
                            "key exchange not implemented, expected key_share extension"
                            HandshakeFailure
        let grp = keyShareEntryGroup serverKeyShare
        unless (checkKeyShareKeyLength serverKeyShare) $
            throwCore $
                Error_Protocol "broken key_share" IllegalParameter
        unless (groupSent == Just grp) $
            throwCore $
                Error_Protocol "received incompatible group for (EC)DHE" IllegalParameter
        usingHState ctx $ setSupportedGroup grp
        usingHState ctx getGroupPrivate >>= fromServerKeyShare serverKeyShare

    makeEarlySecret = do
        mEarlySecretPSK <- usingHState ctx getTLS13EarlySecret
        case mEarlySecretPSK of
            Nothing -> return (initEarlySecret choice Nothing, False)
            Just earlySecretPSK@(BaseSecret sec) -> do
                mSelectedIdentity <- usingState_ ctx getTLS13PreSharedKey
                case mSelectedIdentity of
                    Nothing ->
                        return (initEarlySecret choice Nothing, False)
                    Just (PreSharedKeyServerHello 0) -> do
                        unless (B.length sec == hashSize) $
                            throwCore $
                                Error_Protocol
                                    "selected cipher is incompatible with selected PSK"
                                    IllegalParameter
                        usingHState ctx $ setTLS13HandshakeMode PreSharedKey
                        return (earlySecretPSK, True)
                    Just _ ->
                        throwCore $ Error_Protocol "selected identity out of range" IllegalParameter

    expectEncryptedExtensions (EncryptedExtensions13 eexts) = do
        liftIO $ setALPN ctx MsgTEncryptedExtensions eexts
        st <- usingHState ctx getTLS13RTT0Status
        if st == RTT0Sent
            then case extensionLookup EID_EarlyData eexts of
                Just _ -> do
                    usingHState ctx $ setTLS13HandshakeMode RTT0
                    usingHState ctx $ setTLS13RTT0Status RTT0Accepted
                    return (True, eexts)
                Nothing -> do
                    usingHState ctx $ setTLS13HandshakeMode RTT0
                    usingHState ctx $ setTLS13RTT0Status RTT0Rejected
                    return (False, eexts)
            else return (False, eexts)
    expectEncryptedExtensions p = unexpected (show p) (Just "encrypted extensions")

    expectCertRequest (CertRequest13 token exts) = do
        processCertRequest13 ctx token exts
        recvHandshake13 ctx expectCertAndVerify
    expectCertRequest other = do
        usingHState ctx $ do
            setCertReqToken Nothing
            setCertReqCBdata Nothing
        -- setCertReqSigAlgsCert Nothing
        expectCertAndVerify other

    expectCertAndVerify (Certificate13 _ cc _) = do
        liftIO $ doCertificate cparams ctx cc
        let pubkey = certPubKey $ getCertificate $ getCertificateChainLeaf cc
        ver <- liftIO $ usingState_ ctx getVersion
        checkDigitalSignatureKey ver pubkey
        usingHState ctx $ setPublicKey pubkey
        recvHandshake13hash ctx $ expectCertVerify pubkey
    expectCertAndVerify p = unexpected (show p) (Just "server certificate")

    expectCertVerify pubkey hChSc (CertVerify13 sigAlg sig) = do
        ok <- checkCertVerify ctx pubkey sigAlg sig hChSc
        unless ok $ decryptError "cannot verify CertificateVerify"
    expectCertVerify _ _ p = unexpected (show p) (Just "certificate verify")

    expectFinished (ServerTrafficSecret baseKey) hashValue (Finished13 verifyData) =
        checkFinished ctx usedHash baseKey hashValue verifyData
    expectFinished _ _ p = unexpected (show p) (Just "server finished")

----------------------------------------------------------------

sendClientSecondFlight13 :: ClientParams -> Context -> Pass -> IO ()
sendClientSecondFlight13 cparams ctx (choice, handshakeSecret, clientHandshakeSecret, rtt0accepted, eexts) = do
    hChSf <- transcriptHash ctx
    unless (ctxQUICMode ctx) $
        runPacketFlight ctx $
            sendChangeCipherSpec13 ctx
    when (rtt0accepted && not (ctxQUICMode ctx)) $
        sendPacket13 ctx (Handshake13 [EndOfEarlyData13])
    setTxState ctx usedHash usedCipher clientHandshakeSecret
    sendClientFlight13 cparams ctx usedHash clientHandshakeSecret
    appKey <- switchToApplicationSecret hChSf
    let applicationSecret = triBase appKey
    setResumptionSecret applicationSecret
    let appSecInfo = ApplicationSecretInfo (triClient appKey, triServer appKey)
    contextSync ctx $ SendClientFinished eexts appSecInfo
    handshakeDone13 ctx
  where
    usedCipher = cCipher choice
    usedHash = cHash choice

    switchToApplicationSecret hChSf = do
        ensureRecvComplete ctx
        appKey <- calculateApplicationSecret ctx choice handshakeSecret hChSf
        let serverApplicationSecret0 = triServer appKey
        let clientApplicationSecret0 = triClient appKey
        setTxState ctx usedHash usedCipher clientApplicationSecret0
        setRxState ctx usedHash usedCipher serverApplicationSecret0
        return appKey

    setResumptionSecret applicationSecret = do
        resumptionSecret <- calculateResumptionSecret ctx choice applicationSecret
        usingHState ctx $ setTLS13ResumptionSecret resumptionSecret

----------------------------------------------------------------

processCertRequest13
    :: MonadIO m => Context -> CertReqContext -> [ExtensionRaw] -> m ()
processCertRequest13 ctx token exts = do
    let hsextID = EID_SignatureAlgorithms
    -- caextID = EID_SignatureAlgorithmsCert
    dNames <- canames
    -- The @signature_algorithms@ extension is mandatory.
    hsAlgs <- extalgs hsextID unsighash
    cTypes <- case hsAlgs of
        Just as ->
            let validAs = filter isHashSignatureValid13 as
             in return $ sigAlgsToCertTypes ctx validAs
        Nothing -> throwCore $ Error_Protocol "invalid certificate request" HandshakeFailure
    -- Unused:
    -- caAlgs <- extalgs caextID uncertsig
    usingHState ctx $ do
        setCertReqToken $ Just token
        setCertReqCBdata $ Just (cTypes, hsAlgs, dNames)
  where
    -- setCertReqSigAlgsCert caAlgs

    canames = case extensionLookup
        EID_CertificateAuthorities
        exts of
        Nothing -> return []
        Just ext -> case extensionDecode MsgTCertificateRequest ext of
            Just (CertificateAuthorities names) -> return names
            _ -> throwCore $ Error_Protocol "invalid certificate request" HandshakeFailure
    extalgs extID decons = case extensionLookup extID exts of
        Nothing -> return Nothing
        Just ext -> case extensionDecode MsgTCertificateRequest ext of
            Just e ->
                return $ decons e
            _ -> throwCore $ Error_Protocol "invalid certificate request" HandshakeFailure
    unsighash
        :: SignatureAlgorithms
        -> Maybe [HashAndSignatureAlgorithm]
    unsighash (SignatureAlgorithms a) = Just a

{- Unused for now
uncertsig :: SignatureAlgorithmsCert
          -> Maybe [HashAndSignatureAlgorithm]
uncertsig (SignatureAlgorithmsCert a) = Just a
-}

sendClientFlight13
    :: ClientParams -> Context -> Hash -> ClientTrafficSecret a -> IO ()
sendClientFlight13 cparams ctx usedHash (ClientTrafficSecret baseKey) = do
    chain <- clientChain cparams ctx
    runPacketFlight ctx $ do
        case chain of
            Nothing -> return ()
            Just cc -> usingHState ctx getCertReqToken >>= sendClientData13 cc
        rawFinished <- makeFinished ctx usedHash baseKey
        loadPacket13 ctx $ Handshake13 [rawFinished]
  where
    sendClientData13 chain (Just token) = do
        let (CertificateChain certs) = chain
            certExts = replicate (length certs) []
            cHashSigs = filter isHashSignatureValid13 $ supportedHashSignatures $ ctxSupported ctx
        loadPacket13 ctx $ Handshake13 [Certificate13 token chain certExts]
        case certs of
            [] -> return ()
            _ -> do
                hChSc <- transcriptHash ctx
                pubKey <- getLocalPublicKey ctx
                sigAlg <-
                    liftIO $ getLocalHashSigAlg ctx signatureCompatible13 cHashSigs pubKey
                vfy <- makeCertVerify ctx pubKey sigAlg hChSc
                loadPacket13 ctx $ Handshake13 [vfy]
    --
    sendClientData13 _ _ =
        throwCore $
            Error_Protocol "missing TLS 1.3 certificate request context token" InternalError

postHandshakeAuthClientWith :: ClientParams -> Context -> Handshake13 -> IO ()
postHandshakeAuthClientWith cparams ctx h@(CertRequest13 certReqCtx exts) =
    bracket (saveHState ctx) (restoreHState ctx) $ \_ -> do
        processHandshake13 ctx h
        processCertRequest13 ctx certReqCtx exts
        (usedHash, _, level, applicationSecretN) <- getTxState ctx
        unless (level == CryptApplicationSecret) $
            throwCore $
                Error_Protocol
                    "unexpected post-handshake authentication request"
                    UnexpectedMessage
        sendClientFlight13 cparams ctx usedHash (ClientTrafficSecret applicationSecretN)
postHandshakeAuthClientWith _ _ _ =
    throwCore $
        Error_Protocol
            "unexpected handshake message received in postHandshakeAuthClientWith"
            UnexpectedMessage
