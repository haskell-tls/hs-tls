{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.TLS.Handshake.Server.ClientHello13 (
    processClientHello13,
) where

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Common13
import Network.TLS.Imports
import Network.TLS.Parameters
import Network.TLS.Struct

-- TLS 1.3 or later
processClientHello13
    :: ServerParams
    -> Context
    -> CH
    -> IO (Maybe KeyShareEntry, (Cipher, Hash, Bool))
processClientHello13 sparams ctx CH{..} = do
    when
        (any (\(ExtensionRaw eid _) -> eid == EID_PreSharedKey) $ init chExtensions)
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
        rtt0 =
            lookupAndDecode
                EID_EarlyData
                MsgTClientHello
                chExtensions
                False
                (\(EarlyDataIndication _) -> True)
    if rtt0
        then
            -- mark a 0-RTT attempt before a possible HRR, and before updating the
            -- status again if 0-RTT successful
            setEstablished ctx (EarlyDataNotAllowed 3) -- hardcoding
        else
            -- In the case of HRR, EarlyDataNotAllowed is already set.
            -- It should be cleared here.
            setEstablished ctx NotEstablished
    -- Deciding key exchange from key shares
    let require =
            throwCore $
                Error_Protocol
                    "key exchange not implemented, expected key_share extension"
                    MissingExtension
        extract (KeyShareClientHello kses) = return kses
        extract _ = require
    keyShares <-
        lookupAndDecodeAndDo EID_KeyShare MsgTClientHello chExtensions require extract
    mshare <- findKeyShare keyShares serverGroups
    return (mshare, (usedCipher, usedHash, rtt0))
  where
    ciphersFilteredVersion = intersectCiphers chCiphers serverCiphers
    serverCiphers =
        filter
            (cipherAllowedForVersion TLS13)
            (supportedCiphers $ serverSupported sparams)
    serverGroups = supportedGroups (ctxSupported ctx)

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
