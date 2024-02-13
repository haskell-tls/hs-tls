{-# LANGUAGE LambdaCase #-}

module Network.TLS.Handshake.Client.Common (
    throwMiscErrorOnException,
    doServerKeyExchange,
    doCertificate,
    getLocalHashSigAlg,
    clientChain,
    sigAlgsToCertTypes,
    setALPN,
    contextSync,
) where

import Control.Exception (SomeException)
import Control.Monad.State.Strict
import Data.X509 (ExtKeyUsageFlag (..))

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Credentials
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Certificate
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Control
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.State
import Network.TLS.Imports
import Network.TLS.Packet hiding (getExtensions)
import Network.TLS.Parameters
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Util (catchException)
import Network.TLS.X509

----------------------------------------------------------------

throwMiscErrorOnException :: String -> SomeException -> IO a
throwMiscErrorOnException msg e =
    throwCore $ Error_Misc $ msg ++ ": " ++ show e

----------------------------------------------------------------

doServerKeyExchange :: Context -> ServerKeyXchgAlgorithmData -> IO ()
doServerKeyExchange ctx origSkx = do
    cipher <- usingHState ctx getPendingCipher
    processWithCipher cipher origSkx
  where
    processWithCipher cipher skx =
        case (cipherKeyExchange cipher, skx) of
            (CipherKeyExchange_DHE_RSA, SKX_DHE_RSA dhparams signature) ->
                doDHESignature dhparams signature KX_RSA
            (CipherKeyExchange_DHE_DSA, SKX_DHE_DSA dhparams signature) ->
                doDHESignature dhparams signature KX_DSA
            (CipherKeyExchange_ECDHE_RSA, SKX_ECDHE_RSA ecdhparams signature) ->
                doECDHESignature ecdhparams signature KX_RSA
            (CipherKeyExchange_ECDHE_ECDSA, SKX_ECDHE_ECDSA ecdhparams signature) ->
                doECDHESignature ecdhparams signature KX_ECDSA
            (cke, SKX_Unparsed bytes) -> do
                ver <- usingState_ ctx getVersion
                case decodeReallyServerKeyXchgAlgorithmData ver cke bytes of
                    Left _ ->
                        throwCore $
                            Error_Protocol
                                ("unknown server key exchange received, expecting: " ++ show cke)
                                HandshakeFailure
                    Right realSkx -> processWithCipher cipher realSkx
            -- we need to resolve the result. and recall processWithCipher ..
            (c, _) ->
                throwCore $
                    Error_Protocol
                        ("unknown server key exchange received, expecting: " ++ show c)
                        HandshakeFailure
    doDHESignature dhparams signature kxsAlg = do
        -- FF group selected by the server is verified when generating CKX
        publicKey <- getSignaturePublicKey kxsAlg
        verified <- digitallySignDHParamsVerify ctx dhparams publicKey signature
        unless verified $
            decryptError
                ("bad " ++ pubkeyType publicKey ++ " signature for dhparams " ++ show dhparams)
        usingHState ctx $ setServerDHParams dhparams

    doECDHESignature ecdhparams signature kxsAlg = do
        -- EC group selected by the server is verified when generating CKX
        publicKey <- getSignaturePublicKey kxsAlg
        verified <- digitallySignECDHParamsVerify ctx ecdhparams publicKey signature
        unless verified $
            decryptError ("bad " ++ pubkeyType publicKey ++ " signature for ecdhparams")
        usingHState ctx $ setServerECDHParams ecdhparams

    getSignaturePublicKey kxsAlg = do
        publicKey <- usingHState ctx getRemotePublicKey
        unless (isKeyExchangeSignatureKey kxsAlg publicKey) $
            throwCore $
                Error_Protocol
                    ("server public key algorithm is incompatible with " ++ show kxsAlg)
                    HandshakeFailure
        ver <- usingState_ ctx getVersion
        unless (publicKey `versionCompatible` ver) $
            throwCore $
                Error_Protocol
                    (show ver ++ " has no support for " ++ pubkeyType publicKey)
                    IllegalParameter
        let groups = supportedGroups (ctxSupported ctx)
        unless (satisfiesEcPredicate (`elem` groups) publicKey) $
            throwCore $
                Error_Protocol
                    "server public key has unsupported elliptic curve"
                    IllegalParameter
        return publicKey

----------------------------------------------------------------

doCertificate :: ClientParams -> Context -> CertificateChain -> IO ()
doCertificate cparams ctx certs = do
    when (isNullCertificateChain certs) $
        throwCore $
            Error_Protocol "server certificate missing" DecodeError
    -- run certificate recv hook
    ctxWithHooks ctx (`hookRecvCertificates` certs)
    -- then run certificate validation
    usage <- catchException (wrapCertificateChecks <$> checkCert) rejectOnException
    case usage of
        CertificateUsageAccept -> checkLeafCertificateKeyUsage
        CertificateUsageReject reason -> certificateRejected reason
  where
    shared = clientShared cparams
    checkCert =
        onServerCertificate
            (clientHooks cparams)
            (sharedCAStore shared)
            (sharedValidationCache shared)
            (clientServerIdentification cparams)
            certs
    -- also verify that the certificate optional key usage is compatible
    -- with the intended key-exchange.  This check is not delegated to
    -- x509-validation 'checkLeafKeyUsage' because it depends on negotiated
    -- cipher, which is not available from onServerCertificate parameters.
    -- Additionally, with only one shared ValidationCache, x509-validation
    -- would cache validation result based on a key usage and reuse it with
    -- another key usage.
    checkLeafCertificateKeyUsage = do
        cipher <- usingHState ctx getPendingCipher
        case requiredCertKeyUsage cipher of
            [] -> return ()
            flags -> verifyLeafKeyUsage flags certs

-- Unless result is empty, server certificate must be allowed for at least one
-- of the returned values.  Constraints for RSA-based key exchange are relaxed
-- to avoid rejecting certificates having incomplete extension.
requiredCertKeyUsage :: Cipher -> [ExtKeyUsageFlag]
requiredCertKeyUsage cipher =
    case cipherKeyExchange cipher of
        CipherKeyExchange_RSA -> rsaCompatibility
        CipherKeyExchange_DH_Anon -> [] -- unrestricted
        CipherKeyExchange_DHE_RSA -> rsaCompatibility
        CipherKeyExchange_ECDHE_RSA -> rsaCompatibility
        CipherKeyExchange_DHE_DSA -> [KeyUsage_digitalSignature]
        CipherKeyExchange_DH_DSA -> [KeyUsage_keyAgreement]
        CipherKeyExchange_DH_RSA -> rsaCompatibility
        CipherKeyExchange_ECDH_ECDSA -> [KeyUsage_keyAgreement]
        CipherKeyExchange_ECDH_RSA -> rsaCompatibility
        CipherKeyExchange_ECDHE_ECDSA -> [KeyUsage_digitalSignature]
        CipherKeyExchange_TLS13 -> [KeyUsage_digitalSignature]
  where
    rsaCompatibility =
        [ KeyUsage_digitalSignature
        , KeyUsage_keyEncipherment
        , KeyUsage_keyAgreement
        ]

----------------------------------------------------------------

-- | Return the supported 'CertificateType' values that are
-- compatible with at least one supported signature algorithm.
supportedCtypes
    :: [HashAndSignatureAlgorithm]
    -> [CertificateType]
supportedCtypes hashAlgs =
    nub $ foldr ctfilter [] hashAlgs
  where
    ctfilter x acc = case hashSigToCertType x of
        Just cType
            | cType <= lastSupportedCertificateType ->
                cType : acc
        _ -> acc

clientSupportedCtypes
    :: Context
    -> [CertificateType]
clientSupportedCtypes ctx =
    supportedCtypes $ supportedHashSignatures $ ctxSupported ctx

sigAlgsToCertTypes
    :: Context
    -> [HashAndSignatureAlgorithm]
    -> [CertificateType]
sigAlgsToCertTypes ctx hashSigs =
    filter (`elem` supportedCtypes hashSigs) $ clientSupportedCtypes ctx

----------------------------------------------------------------

-- | When the server requests a client certificate, we try to
-- obtain a suitable certificate chain and private key via the
-- callback in the client parameters.  It is OK for the callback
-- to return an empty chain, in many cases the client certificate
-- is optional.  If the client wishes to abort the handshake for
-- lack of a suitable certificate, it can throw an exception in
-- the callback.
--
-- The return value is 'Nothing' when no @CertificateRequest@ was
-- received and no @Certificate@ message needs to be sent. An empty
-- chain means that an empty @Certificate@ message needs to be sent
-- to the server, naturally without a @CertificateVerify@.  A non-empty
-- 'CertificateChain' is the chain to send to the server along with
-- a corresponding 'CertificateVerify'.
--
-- With TLS < 1.2 the server's @CertificateRequest@ does not carry
-- a signature algorithm list.  It has a list of supported public
-- key signing algorithms in the @certificate_types@ field.  The
-- hash is implicit.  It is 'SHA1' for DSA and 'SHA1_MD5' for RSA.
--
-- With TLS == 1.2 the server's @CertificateRequest@ always has a
-- @supported_signature_algorithms@ list, as a fixed component of
-- the structure.  This list is (wrongly) overloaded to also limit
-- X.509 signatures in the client's certificate chain.  The BCP
-- strategy is to find a compatible chain if possible, but else
-- ignore the constraint, and let the server verify the chain as it
-- sees fit.  The @supported_signature_algorithms@ field is only
-- obligatory with respect to signatures on TLS messages, in this
-- case the @CertificateVerify@ message.  The @certificate_types@
-- field is still included.
--
-- With TLS 1.3 the server's @CertificateRequest@ has a mandatory
-- @signature_algorithms@ extension, the @signature_algorithms_cert@
-- extension, which is optional, carries a list of algorithms the
-- server promises to support in verifying the certificate chain.
-- As with TLS 1.2, the client's makes a /best-effort/ to deliver
-- a compatible certificate chain where all the CA signatures are
-- known to be supported, but it should not abort the connection
-- just because the chain might not work out, just send the best
-- chain you have and let the server worry about the rest.  The
-- supported public key algorithms are now inferred from the
-- @signature_algorithms@ extension and @certificate_types@ is
-- gone.
--
-- With TLS 1.3, we synthesize and store a @certificate_types@
-- field at the time that the server's @CertificateRequest@
-- message is received.  This is then present across all the
-- protocol versions, and can be used to determine whether
-- a @CertificateRequest@ was received or not.
--
-- If @signature_algorithms@ is 'Nothing', then we're doing
-- TLS 1.0 or 1.1.  The @signature_algorithms_cert@ extension
-- is optional in TLS 1.3, and so the application callback
-- will not be able to distinguish between TLS 1.[01] and
-- TLS 1.3 with no certificate algorithm hints, but this
-- just simplifies the chain selection process, all CA
-- signatures are OK.
clientChain :: ClientParams -> Context -> IO (Maybe CertificateChain)
clientChain cparams ctx =
    usingHState ctx getCertReqCBdata >>= \case
        Nothing -> return Nothing
        Just cbdata -> do
            let callback = onCertificateRequest $ clientHooks cparams
            chain <-
                liftIO $
                    callback cbdata
                        `catchException` throwMiscErrorOnException "certificate request callback failed"
            case chain of
                Nothing ->
                    return $ Just $ CertificateChain []
                Just (CertificateChain [], _) ->
                    return $ Just $ CertificateChain []
                Just cred@(cc, _) ->
                    do
                        let (cTypes, _, _) = cbdata
                        storePrivInfoClient ctx cTypes cred
                        return $ Just cc

-- | Store the keypair and check that it is compatible with the current protocol
-- version and a list of 'CertificateType' values.
storePrivInfoClient
    :: Context
    -> [CertificateType]
    -> Credential
    -> IO ()
storePrivInfoClient ctx cTypes (cc, privkey) = do
    pubkey <- storePrivInfo ctx cc privkey
    unless (certificateCompatible pubkey cTypes) $
        throwCore $
            Error_Protocol
                (pubkeyType pubkey ++ " credential does not match allowed certificate types")
                InternalError
    ver <- usingState_ ctx getVersion
    unless (pubkey `versionCompatible` ver) $
        throwCore $
            Error_Protocol
                (pubkeyType pubkey ++ " credential is not supported at version " ++ show ver)
                InternalError

----------------------------------------------------------------

-- | Return a most preferred 'HandAndSignatureAlgorithm' that is compatible with
-- the local key and server's signature algorithms (both already saved).  Must
-- only be called for TLS versions 1.2 and up, with compatibility function
-- 'signatureCompatible' or 'signatureCompatible13' based on version.
--
-- The values in the server's @signature_algorithms@ extension are
-- in descending order of preference.  However here the algorithms
-- are selected by client preference in @cHashSigs@.
getLocalHashSigAlg
    :: Context
    -> (PubKey -> HashAndSignatureAlgorithm -> Bool)
    -> [HashAndSignatureAlgorithm]
    -> PubKey
    -> IO HashAndSignatureAlgorithm
getLocalHashSigAlg ctx isCompatible cHashSigs pubKey = do
    -- Must be present with TLS 1.2 and up.
    (Just (_, Just hashSigs, _)) <- usingHState ctx getCertReqCBdata
    let want =
            (&&)
                <$> isCompatible pubKey
                <*> flip elem hashSigs
    case find want cHashSigs of
        Just best -> return best
        Nothing -> throwCore $ Error_Protocol (keyerr pubKey) HandshakeFailure
  where
    keyerr k = "no " ++ pubkeyType k ++ " hash algorithm in common with the server"

----------------------------------------------------------------

setALPN :: Context -> MessageType -> [ExtensionRaw] -> IO ()
setALPN ctx msgt exts = case extensionLookup EID_ApplicationLayerProtocolNegotiation exts
    >>= extensionDecode msgt of
    Just (ApplicationLayerProtocolNegotiation [proto]) -> usingState_ ctx $ do
        mprotos <- getClientALPNSuggest
        case mprotos of
            Just protos -> when (proto `elem` protos) $ do
                setExtensionALPN True
                setNegotiatedProtocol proto
            _ -> return ()
    _ -> return ()

----------------------------------------------------------------

contextSync :: Context -> ClientState -> IO ()
contextSync ctx ctl = case ctxHandshakeSync ctx of
    HandshakeSync sync _ -> sync ctx ctl
