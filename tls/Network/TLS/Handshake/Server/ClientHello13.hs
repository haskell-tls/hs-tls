{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.TLS.Handshake.Server.ClientHello13 (
    processClientHello13,
) where

import qualified Data.ByteString as B

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.State
import Network.TLS.IO.Encode
import Network.TLS.Imports
import Network.TLS.Packet
import Network.TLS.Parameters
import Network.TLS.Session
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Types

-- TLS 1.3 or later
processClientHello13
    :: ServerParams
    -> Context
    -> CHP
    -> IO
        ( Maybe KeyShareEntry
        , (Cipher, Hash, Bool)
        , (SecretPair EarlySecret, [ExtensionRaw], Bool, Bool)
        )
processClientHello13 sparams ctx chp@CHP{..} = do
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
    let triple = (usedCipher, usedHash, rtt0)
    pskEarlySecret <- pskAndEarlySecret sparams ctx triple chp
    clientHello <- fromJust <$> usingHState ctx getClientHello
    void $ updateTranscriptHash12 ctx clientHello
    return (mshare, triple, pskEarlySecret)
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

pskAndEarlySecret
    :: ServerParams
    -> Context
    -> (Cipher, Hash, Bool)
    -> CHP
    -> IO (SecretPair EarlySecret, [ExtensionRaw], Bool, Bool)
pskAndEarlySecret sparams ctx (usedCipher, usedHash, rtt0) CHP{..} = do
    (psk, binderInfo, is0RTTvalid) <- choosePSK
    earlyKey <- calculateEarlySecret ctx choice (Left psk)
    let earlySecret = pairBase earlyKey
        authenticated = isJust binderInfo
    preSharedKeyExt <- checkBinder earlySecret binderInfo
    return (earlyKey, preSharedKeyExt, authenticated, is0RTTvalid)
  where
    choice = makeCipherChoice TLS13 usedCipher

    choosePSK =
        lookupAndDecodeAndDo
            EID_PreSharedKey
            MsgTClientHello
            chExtensions
            (return (zero, Nothing, False))
            selectPSK

    selectPSK (PreSharedKeyClientHello (PskIdentity identity obfAge : _) bnds@(bnd : _)) = do
        when (null dhModes) $
            throwCore $
                Error_Protocol "no psk_key_exchange_modes extension" MissingExtension
        if PSK_DHE_KE `elem` dhModes
            then do
                let len = sum (map (\x -> B.length x + 1) bnds) + 2
                    mgr = sharedSessionManager $ serverShared sparams
                -- sessionInvalidate is not used for TLS 1.3
                -- because PSK is always changed.
                -- So, identity is not stored in Context.
                msdata <-
                    if rtt0
                        then sessionResumeOnlyOnce mgr identity
                        else sessionResume mgr identity
                case msdata of
                    Just sdata -> do
                        let tinfo = fromJust $ sessionTicketInfo sdata
                            psk = sessionSecret sdata
                        isFresh <- checkFreshness tinfo obfAge
                        (isPSKvalid, is0RTTvalid) <- checkSessionEquality sdata
                        if isPSKvalid && isFresh
                            then return (psk, Just (bnd, 0 :: Int, len), is0RTTvalid)
                            else -- fall back to full handshake
                                return (zero, Nothing, False)
                    _ -> return (zero, Nothing, False)
            else return (zero, Nothing, False)
    selectPSK _ = return (zero, Nothing, False)

    checkBinder _ Nothing = return []
    checkBinder earlySecret (Just (binder, n, tlen)) = do
        ch <- fromJust <$> usingHState ctx getClientHello
        let ech = encodeHandshake ch
        binder' <- makePSKBinder ctx earlySecret usedHash tlen ech
        unless (binder == binder') $
            decryptError "PSK binder validation failed"
        return [toExtensionRaw $ PreSharedKeyServerHello $ fromIntegral n]

    checkSessionEquality sdata = do
        msni <- usingState_ ctx getClientSNI
        -- ALPN should be checked.
        -- But it's an extension in EE, sigh.
        --        malpn <- usingState_ ctx getNegotiatedProtocol
        let isSameSNI = sessionClientSNI sdata == msni
            isSameCipher = sessionCipher sdata == cipherID usedCipher
            ciphers = supportedCiphers $ serverSupported sparams
            scid = sessionCipher sdata
            isSameKDF = case findCipher scid ciphers of
                Nothing -> False
                Just c -> cipherHash c == cipherHash usedCipher
            isSameVersion = TLS13 == sessionVersion sdata
            --            isSameALPN = sessionALPN sdata == malpn
            isPSKvalid = isSameKDF && isSameSNI -- fixme: SNI is not required
            is0RTTvalid = isSameVersion && isSameCipher -- && isSameALPN
        return (isPSKvalid, is0RTTvalid)

    dhModes =
        lookupAndDecode
            EID_PskKeyExchangeModes
            MsgTClientHello
            chExtensions
            []
            (\(PskKeyExchangeModes ms) -> ms)

    hashSize = hashDigestSize usedHash
    zero = B.replicate hashSize 0
