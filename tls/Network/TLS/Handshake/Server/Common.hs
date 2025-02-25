{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.Server.Common (
    applicationProtocol,
    checkValidClientCertChain,
    clientCertificate,
    credentialDigitalSignatureKey,
    filterCredentials,
    filterCredentialsWithHashSignatures,
    makeCredentialPredicate,
    isCredentialAllowed,
    storePrivInfoServer,
    hashAndSignaturesInCommon,
    processRecordSizeLimit,
) where

import Control.Monad.State.Strict
import Data.X509 (ExtKeyUsageFlag (..))

import Network.TLS.Context.Internal
import Network.TLS.Credentials
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Certificate
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.State
import Network.TLS.Imports
import Network.TLS.Parameters
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Util (catchException)
import Network.TLS.X509

checkValidClientCertChain
    :: MonadIO m => Context -> String -> m CertificateChain
checkValidClientCertChain ctx errmsg = do
    chain <- usingHState ctx getClientCertChain
    let throwerror = Error_Protocol errmsg UnexpectedMessage
    case chain of
        Nothing -> throwCore throwerror
        Just cc
            | isNullCertificateChain cc -> throwCore throwerror
            | otherwise -> return cc

credentialDigitalSignatureKey :: Credential -> Maybe PubKey
credentialDigitalSignatureKey cred
    | isDigitalSignaturePair keys = Just pubkey
    | otherwise = Nothing
  where
    keys@(pubkey, _) = credentialPublicPrivateKeys cred

filterCredentials :: (Credential -> Bool) -> Credentials -> Credentials
filterCredentials p (Credentials l) = Credentials (filter p l)

-- ECDSA keys are tested against supported elliptic curves until TLS12 but
-- not after.  With TLS13, the curve is linked to the signature algorithm
-- and client support is tested with signatureCompatible13.
makeCredentialPredicate :: Version -> [ExtensionRaw] -> (Group -> Bool)
makeCredentialPredicate ver exts
    | ver >= TLS13 = const True
    | otherwise =
        lookupAndDecode
            EID_SupportedGroups
            MsgTClientHello
            exts
            (const True)
            (\(SupportedGroups sg) -> (`elem` sg))

isCredentialAllowed :: Version -> (Group -> Bool) -> Credential -> Bool
isCredentialAllowed ver p cred =
    pubkey `versionCompatible` ver && satisfiesEcPredicate p pubkey
  where
    (pubkey, _) = credentialPublicPrivateKeys cred

-- Filters a list of candidate credentials with credentialMatchesHashSignatures.
--
-- Algorithms to filter with are taken from "signature_algorithms_cert"
-- extension when it exists, else from "signature_algorithms" when clients do
-- not implement the new extension (see RFC 8446 section 4.2.3).
--
-- Resulting credential list can be used as input to the hybrid cipher-and-
-- certificate selection for TLS12, or to the direct certificate selection
-- simplified with TLS13.  As filtering credential signatures with client-
-- advertised algorithms is not supposed to cause negotiation failure, in case
-- of dead end with the subsequent selection process, this process should always
-- be restarted with the unfiltered credential list as input (see fallback
-- certificate chains, described in same RFC section).
--
-- Calling code should not forget to apply constraints of extension
-- "signature_algorithms" to any signature-based key exchange derived from the
-- output credentials.  Respecting client constraints on KX signatures is
-- mandatory but not implemented by this function.
filterCredentialsWithHashSignatures
    :: [ExtensionRaw] -> Credentials -> Credentials
filterCredentialsWithHashSignatures exts =
    lookupAndDecode
        EID_SignatureAlgorithmsCert
        MsgTClientHello
        exts
        lookupSignatureAlgorithms
        (\(SignatureAlgorithmsCert sas) -> withAlgs sas)
  where
    lookupSignatureAlgorithms =
        lookupAndDecode
            EID_SignatureAlgorithms
            MsgTClientHello
            exts
            id
            (\(SignatureAlgorithms sas) -> withAlgs sas)
    withAlgs sas = filterCredentials (credentialMatchesHashSignatures sas)

storePrivInfoServer :: MonadIO m => Context -> Credential -> m ()
storePrivInfoServer ctx (cc, privkey) = void (storePrivInfo ctx cc privkey)

-- ALPN (Application Layer Protocol Negotiation)
applicationProtocol
    :: Context -> [ExtensionRaw] -> ServerParams -> IO (Maybe ExtensionRaw)
applicationProtocol ctx exts sparams = case onALPN of
    Nothing -> return Nothing
    Just io ->
        lookupAndDecodeAndDo
            EID_ApplicationLayerProtocolNegotiation
            MsgTClientHello
            exts
            (return Nothing)
            $ select io
  where
    onALPN = onALPNClientSuggest $ serverHooks sparams
    select io (ApplicationLayerProtocolNegotiation protos) = do
        proto <- io protos
        when (proto == "") $
            throwCore $
                Error_Protocol "no supported application protocols" NoApplicationProtocol
        usingState_ ctx $ do
            setExtensionALPN True
            setNegotiatedProtocol proto
        let alpn = ApplicationLayerProtocolNegotiation [proto]
        return $ Just $ toExtensionRaw alpn

clientCertificate :: ServerParams -> Context -> CertificateChain -> IO ()
clientCertificate sparams ctx certs = do
    -- run certificate recv hook
    ctxWithHooks ctx (`hookRecvCertificates` certs)
    -- Call application callback to see whether the
    -- certificate chain is acceptable.
    --
    usage <-
        liftIO $
            catchException
                (onClientCertificate (serverHooks sparams) certs)
                rejectOnException
    case usage of
        CertificateUsageAccept -> verifyLeafKeyUsage [KeyUsage_digitalSignature] certs
        CertificateUsageReject reason -> certificateRejected reason

    -- Remember cert chain for later use.
    --
    usingHState ctx $ setClientCertChain certs

----------------------------------------------------------------

-- The values in the "signature_algorithms" extension
-- are in descending order of preference.
-- However here the algorithms are selected according
-- to server preference in 'supportedHashSignatures'.
hashAndSignaturesInCommon
    :: [HashAndSignatureAlgorithm] -> [ExtensionRaw] -> [HashAndSignatureAlgorithm]
hashAndSignaturesInCommon sHashSigs exts = sHashSigs `intersect` cHashSigs
  where
    -- See Section 7.4.1.4.1 of RFC 5246.
    defVal =
        [ (HashSHA1, SignatureECDSA)
        , (HashSHA1, SignatureRSA)
        , (HashSHA1, SignatureDSA)
        ]
    cHashSigs =
        lookupAndDecode
            EID_SignatureAlgorithms
            MsgTClientHello
            exts
            defVal
            (\(SignatureAlgorithms sas) -> sas)

processRecordSizeLimit
    :: Context -> [ExtensionRaw] -> Bool -> IO (Maybe ExtensionRaw)
processRecordSizeLimit ctx chExts tls13 = do
    let mmylim = limitRecordSize $ sharedLimit $ ctxShared ctx
    setMyRecordLimit ctx mmylim
    case mmylim of
        Nothing -> return Nothing
        Just mylim -> do
            lookupAndDecodeAndDo
                EID_RecordSizeLimit
                MsgTClientHello
                chExts
                (return ())
                (setPeerRecordSizeLimit ctx tls13)
            peerSentRSL <- checkPeerRecordLimit ctx
            if peerSentRSL
                then do
                    let mysiz = fromIntegral mylim + if tls13 then 1 else 0
                        rsl = RecordSizeLimit mysiz
                    return $ Just $ toExtensionRaw rsl
                else return Nothing
