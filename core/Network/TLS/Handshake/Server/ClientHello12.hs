{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.Server.ClientHello12 (
    processClinetHello12,
) where

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Credentials
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Server.Common
import Network.TLS.Handshake.Signature
import Network.TLS.Imports
import Network.TLS.Parameters
import Network.TLS.State
import Network.TLS.Struct

-- TLS 1.2 or earlier
processClinetHello12
    :: ServerParams
    -> Context
    -> Handshake
    -> IO (Cipher, Maybe Credential)
processClinetHello12 sparams ctx (ClientHello _ _ _ ciphers _ exts _) = do
    serverName <- usingState_ ctx getClientSNI
    extraCreds <- onServerNameIndication (serverHooks sparams) serverName
    let allCreds =
            filterCredentials (isCredentialAllowed TLS12 exts) $
                extraCreds `mappend` sharedCredentials (ctxShared ctx)

    -- When selecting a cipher we must ensure that it is allowed for the
    -- TLS version but also that all its key-exchange requirements
    -- will be met.

    -- Some ciphers require a signature and a hash.  With TLS 1.2 the hash
    -- algorithm is selected from a combination of server configuration and
    -- the client "supported_signatures" extension.  So we cannot pick
    -- such a cipher if no hash is available for it.  It's best to skip this
    -- cipher and pick another one (with another key exchange).

    -- Cipher selection is performed in two steps: first server credentials
    -- are flagged as not suitable for signature if not compatible with
    -- negotiated signature parameters.  Then ciphers are evalutated from
    -- the resulting credentials.

    let possibleGroups = negotiatedGroupsInCommon ctx exts
        possibleECGroups = possibleGroups `intersect` availableECGroups
        possibleFFGroups = possibleGroups `intersect` availableFFGroups
        hasCommonGroupForECDHE = not (null possibleECGroups)
        hasCommonGroupForFFDHE = not (null possibleFFGroups)
        hasCustomGroupForFFDHE = isJust (serverDHEParams sparams)
        canFFDHE = hasCustomGroupForFFDHE || hasCommonGroupForFFDHE
        hasCommonGroup cipher =
            case cipherKeyExchange cipher of
                CipherKeyExchange_DH_Anon -> canFFDHE
                CipherKeyExchange_DHE_RSA -> canFFDHE
                CipherKeyExchange_DHE_DSA -> canFFDHE
                CipherKeyExchange_ECDHE_RSA -> hasCommonGroupForECDHE
                CipherKeyExchange_ECDHE_ECDSA -> hasCommonGroupForECDHE
                _ -> True -- group not used

        -- Ciphers are selected according to TLS version, availability of
        -- (EC)DHE group and credential depending on key exchange.
        cipherAllowed cipher = cipherAllowedForVersion TLS12 cipher && hasCommonGroup cipher
        selectCipher credentials signatureCredentials = filter cipherAllowed (commonCiphers credentials signatureCredentials)

        (creds, signatureCreds, ciphersFilteredVersion) =
            let -- Build a list of all hash/signature algorithms in common between
                -- client and server.
                possibleHashSigAlgs = hashAndSignaturesInCommon ctx exts

                -- Check that a candidate signature credential will be compatible with
                -- client & server hash/signature algorithms.  This returns Just Int
                -- in order to sort credentials according to server hash/signature
                -- preference.  When the certificate has no matching hash/signature in
                -- 'possibleHashSigAlgs' the result is Nothing, and the credential will
                -- not be used to sign.  This avoids a failure later in 'decideHashSig'.
                signingRank cred =
                    case credentialDigitalSignatureKey cred of
                        Just pub -> findIndex (pub `signatureCompatible`) possibleHashSigAlgs
                        Nothing -> Nothing

                -- Finally compute credential lists and resulting cipher list.
                --
                -- We try to keep certificates supported by the client, but
                -- fallback to all credentials if this produces no suitable result
                -- (see RFC 5246 section 7.4.2 and RFC 8446 section 4.4.2.2).
                -- The condition is based on resulting (EC)DHE ciphers so that
                -- filtering credentials does not give advantage to a less secure
                -- key exchange like CipherKeyExchange_RSA or CipherKeyExchange_DH_Anon.
                cltCreds = filterCredentialsWithHashSignatures exts allCreds
                sigCltCreds = filterSortCredentials signingRank cltCreds
                sigAllCreds = filterSortCredentials signingRank allCreds
                cltCiphers = selectCipher cltCreds sigCltCreds
                allCiphers = selectCipher allCreds sigAllCreds

                resultTuple =
                    if cipherListCredentialFallback cltCiphers
                        then (allCreds, sigAllCreds, allCiphers)
                        else (cltCreds, sigCltCreds, cltCiphers)
             in resultTuple

    -- The shared cipherlist can become empty after filtering for compatible
    -- creds, check now before calling onCipherChoosing, which does not handle
    -- empty lists.
    when (null ciphersFilteredVersion) $
        throwCore $
            Error_Protocol "no cipher in common with the TLS 1.2 client" HandshakeFailure

    let usedCipher = onCipherChoosing (serverHooks sparams) TLS12 ciphersFilteredVersion

    cred <- case cipherKeyExchange usedCipher of
        CipherKeyExchange_RSA -> return $ credentialsFindForDecrypting creds
        CipherKeyExchange_DH_Anon -> return Nothing
        CipherKeyExchange_DHE_RSA -> return $ credentialsFindForSigning KX_RSA signatureCreds
        CipherKeyExchange_DHE_DSA -> return $ credentialsFindForSigning KX_DSA signatureCreds
        CipherKeyExchange_ECDHE_RSA -> return $ credentialsFindForSigning KX_RSA signatureCreds
        CipherKeyExchange_ECDHE_ECDSA -> return $ credentialsFindForSigning KX_ECDSA signatureCreds
        _ ->
            throwCore $
                Error_Protocol "key exchange algorithm not implemented" HandshakeFailure

    return (usedCipher, cred)
  where
    commonCiphers creds sigCreds = filter ((`elem` ciphers) . cipherID) (getCiphers sparams creds sigCreds)
processClinetHello12 _ _ _ = error "processClinetHello12"

hashAndSignaturesInCommon
    :: Context -> [ExtensionRaw] -> [HashAndSignatureAlgorithm]
hashAndSignaturesInCommon ctx exts =
    let cHashSigs = case extensionLookup EID_SignatureAlgorithms exts
            >>= extensionDecode MsgTClientHello of
            -- See Section 7.4.1.4.1 of RFC 5246.
            Nothing ->
                [ (HashSHA1, SignatureECDSA)
                , (HashSHA1, SignatureRSA)
                , (HashSHA1, SignatureDSA)
                ]
            Just (SignatureAlgorithms sas) -> sas
        sHashSigs = supportedHashSignatures $ ctxSupported ctx
     in -- The values in the "signature_algorithms" extension
        -- are in descending order of preference.
        -- However here the algorithms are selected according
        -- to server preference in 'supportedHashSignatures'.
        sHashSigs `intersect` cHashSigs

negotiatedGroupsInCommon :: Context -> [ExtensionRaw] -> [Group]
negotiatedGroupsInCommon ctx exts = case extensionLookup EID_SupportedGroups exts
    >>= extensionDecode MsgTClientHello of
    Just (SupportedGroups clientGroups) ->
        let serverGroups = supportedGroups (ctxSupported ctx)
         in serverGroups `intersect` clientGroups
    _ -> []

filterSortCredentials
    :: Ord a => (Credential -> Maybe a) -> Credentials -> Credentials
filterSortCredentials rankFun (Credentials creds) =
    let orderedPairs = sortOn fst [(rankFun cred, cred) | cred <- creds]
     in Credentials [cred | (Just _, cred) <- orderedPairs]

-- returns True if certificate filtering with "signature_algorithms_cert" /
-- "signature_algorithms" produced no ephemeral D-H nor TLS13 cipher (so
-- handshake with lower security)
cipherListCredentialFallback :: [Cipher] -> Bool
cipherListCredentialFallback = all nonDH
  where
    nonDH x = case cipherKeyExchange x of
        CipherKeyExchange_DHE_RSA -> False
        CipherKeyExchange_DHE_DSA -> False
        CipherKeyExchange_ECDHE_RSA -> False
        CipherKeyExchange_ECDHE_ECDSA -> False
        CipherKeyExchange_TLS13 -> False
        _ -> True

-- We filter our allowed ciphers here according to dynamic credential lists.
-- Credentials 'creds' come from server parameters but also SNI callback.
-- When the key exchange requires a signature, we use a
-- subset of this list named 'sigCreds'.  This list has been filtered in order
-- to remove certificates that are not compatible with hash/signature
-- restrictions (TLS 1.2).
getCiphers :: ServerParams -> Credentials -> Credentials -> [Cipher]
getCiphers sparams creds sigCreds = filter authorizedCKE (supportedCiphers $ serverSupported sparams)
  where
    authorizedCKE cipher =
        case cipherKeyExchange cipher of
            CipherKeyExchange_RSA -> canEncryptRSA
            CipherKeyExchange_DH_Anon -> True
            CipherKeyExchange_DHE_RSA -> canSignRSA
            CipherKeyExchange_DHE_DSA -> canSignDSA
            CipherKeyExchange_ECDHE_RSA -> canSignRSA
            CipherKeyExchange_ECDHE_ECDSA -> canSignECDSA
            -- unimplemented: non ephemeral DH & ECDH.
            -- Note, these *should not* be implemented, and have
            -- (for example) been removed in OpenSSL 1.1.0
            --
            CipherKeyExchange_DH_DSA -> False
            CipherKeyExchange_DH_RSA -> False
            CipherKeyExchange_ECDH_ECDSA -> False
            CipherKeyExchange_ECDH_RSA -> False
            CipherKeyExchange_TLS13 -> False -- not reached
    canSignDSA = KX_DSA `elem` signingAlgs
    canSignRSA = KX_RSA `elem` signingAlgs
    canSignECDSA = KX_ECDSA `elem` signingAlgs
    canEncryptRSA = isJust $ credentialsFindForDecrypting creds
    signingAlgs = credentialsListSigningAlgorithms sigCreds
