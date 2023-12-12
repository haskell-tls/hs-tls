{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.Server.ClientHello13 (
    processClientHello13,
    sendHRR,
) where

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Random
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.Parameters
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13

-- TLS 1.3 or later
processClientHello13
    :: ServerParams
    -> Context
    -> Handshake
    -> IO (Maybe KeyShareEntry, (Cipher, Hash, Bool))
processClientHello13 sparams ctx (ClientHello _ _ _ clientCiphers _ exts _) = do
    when
        (any (\(ExtensionRaw eid _) -> eid == EID_PreSharedKey) $ init exts)
        $ throwCore
        $ Error_Protocol "extension pre_shared_key must be last" IllegalParameter
    -- Deciding cipher.
    -- The shared cipherlist can become empty after filtering for compatible
    -- creds, check now before calling onCipherChoosing, which does not handle
    -- empty lists.
    when (null ciphersFilteredVersion) $
        throwCore $
            Error_Protocol "no cipher in common with the TLS 1.3 client" HandshakeFailure
    let usedCipher = onCipherChoosing (serverHooks sparams) TLS13 ciphersFilteredVersion
        usedHash = cipherHash usedCipher
        rtt0 = case extensionLookup EID_EarlyData exts >>= extensionDecode MsgTClientHello of
            Just (EarlyDataIndication _) -> True
            Nothing -> False
    when rtt0 $
        -- mark a 0-RTT attempt before a possible HRR, and before updating the
        -- status again if 0-RTT successful
        setEstablished ctx (EarlyDataNotAllowed 3) -- hardcoding
        -- Deciding key exchange from key shares
    keyShares <- case extensionLookup EID_KeyShare exts of
        Nothing ->
            throwCore $
                Error_Protocol
                    "key exchange not implemented, expected key_share extension"
                    MissingExtension
        Just kss -> case extensionDecode MsgTClientHello kss of
            Just (KeyShareClientHello kses) -> return kses
            Just _ ->
                error "processClientHello13: invalid KeyShare value"
            _ ->
                throwCore $ Error_Protocol "broken key_share" DecodeError
    mshare <- findKeyShare keyShares serverGroups
    return (mshare, (usedCipher, usedHash, rtt0))
  where
    ciphersFilteredVersion = filter ((`elem` clientCiphers) . cipherID) serverCiphers
    serverCiphers =
        filter
            (cipherAllowedForVersion TLS13)
            (supportedCiphers $ serverSupported sparams)
    serverGroups = supportedGroups (ctxSupported ctx)
processClientHello13 _ _ _ = error "processClientHello13"

findKeyShare :: [KeyShareEntry] -> [Group] -> IO (Maybe KeyShareEntry)
findKeyShare ks ggs = go ggs
  where
    go [] = return Nothing
    go (g : gs) = case filter (grpEq g) ks of
        [] -> go gs
        [k] -> do
            unless (checkKeyShareKeyLength k) $
                throwCore $
                    Error_Protocol "broken key_share" IllegalParameter
            return $ Just k
        _ -> throwCore $ Error_Protocol "duplicated key_share" IllegalParameter
    grpEq g ent = g == keyShareEntryGroup ent

sendHRR :: Context -> (Cipher, a, b) -> Handshake -> IO ()
sendHRR ctx (usedCipher, _, _) (ClientHello _ _ clientSession _ _ exts _) = do
    twice <- usingState_ ctx getTLS13HRR
    when twice $
        throwCore $
            Error_Protocol "Hello retry not allowed again" HandshakeFailure
    usingState_ ctx $ setTLS13HRR True
    failOnEitherError $ usingHState ctx $ setHelloParameters13 usedCipher
    let clientGroups = case extensionLookup EID_SupportedGroups exts
            >>= extensionDecode MsgTClientHello of
            Just (SupportedGroups gs) -> gs
            Nothing -> []
        possibleGroups = serverGroups `intersect` clientGroups
    case possibleGroups of
        [] ->
            throwCore $
                Error_Protocol "no group in common with the client for HRR" HandshakeFailure
        g : _ -> do
            let serverKeyShare = extensionEncode $ KeyShareHRR g
                selectedVersion = extensionEncode $ SupportedVersionsServerHello TLS13
                extensions =
                    [ ExtensionRaw EID_KeyShare serverKeyShare
                    , ExtensionRaw EID_SupportedVersions selectedVersion
                    ]
                hrr = ServerHello13 hrrRandom clientSession (cipherID usedCipher) extensions
            usingHState ctx $ setTLS13HandshakeMode HelloRetryRequest
            runPacketFlight ctx $ do
                loadPacket13 ctx $ Handshake13 [hrr]
                sendChangeCipherSpec13 ctx
  where
    serverGroups = supportedGroups (ctxSupported ctx)
sendHRR _ _ _ = error "sendHRR"
