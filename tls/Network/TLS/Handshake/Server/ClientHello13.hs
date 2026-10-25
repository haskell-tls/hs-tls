{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.TLS.Handshake.Server.ClientHello13 (
    processClientHello13,
    SelectKeyShareResult (..),
) where

import qualified Data.ByteString as B

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Common (restoreClientCertificate)
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Server.Common
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.State
import Network.TLS.IO.Encode
import Network.TLS.Imports
import Network.TLS.Parameters
import Network.TLS.Session
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Types

limitSupportedGroups :: Int
limitSupportedGroups = 64

-- TLS 1.3 or later
processClientHello13
    :: ServerParams
    -> Context
    -> ClientHello
    -> IO
        ( SelectKeyShareResult
        , (Cipher, Hash, Bool) -- rtt0
        , (SecretPair EarlySecret, [ExtensionRaw], Bool, Bool, Maybe ByteString)
          -- authenticated, is0RTTvalid, ticket ALPN
        )
processClientHello13 sparams ctx ch@CH{..} = do
    when
        (any (\(ExtensionRaw eid _) -> eid == EID_PreSharedKey) $ init chExtensions)
        $ throwCore
        $ Error_Protocol "extension pre_shared_key must be last" IllegalParameter
    -- RFC 9846 Section 9.2: the extensions a TLS 1.3 ClientHello must have.
    let has eid = isJust $ extensionLookup eid chExtensions
        missing reason = throwCore $ Error_Protocol reason MissingExtension
    unless (has EID_PreSharedKey) $ do
        unless (has EID_SignatureAlgorithms) $
            missing "no signature_algorithms extension without pre_shared_key"
        unless (has EID_SupportedGroups) $
            missing "no supported_groups extension without pre_shared_key"
    when (has EID_SupportedGroups /= has EID_KeyShare) $
        missing "supported_groups and key_share must come together"
    -- Deciding cipher.
    -- The shared cipherlist can become empty after filtering for compatible
    -- creds, check now before calling onCipherChoosing, which does not handle
    -- empty lists.
    when (null ciphersFilteredVersion) $
        throwCore $
            Error_Protocol "no cipher in common with the TLS 1.3 client" HandshakeFailure
    usedCipher <- chooseCipher sparams TLS13 chCiphers ciphersFilteredVersion
    let usedHash = cipherHash usedCipher
        rtt0 =
            lookupAndDecode
                EID_EarlyData
                MsgTClientHello
                chExtensions
                False
                (\(EarlyDataIndication _) -> True)
    if rtt0
        then
            -- Skip up to this many bytes of rejected early data: a record's worth
            -- at least, even if early data is not accepted (0 by default), and
            -- more only if the server accepts more.  Updated if 0-RTT succeeds.
            setEstablished
                ctx
                (EarlyDataNotAllowed (max 16384 (serverEarlyDataSize sparams)))
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
    let allClientGroups =
            lookupAndDecode
                EID_SupportedGroups
                MsgTClientHello
                chExtensions
                []
                (\(SupportedGroups gs) -> gs)
        clientGroups = take limitSupportedGroups allClientGroups
    -- RFC 9846 Section 4.2.8: after HelloRetryRequest, only the selected
    -- group is offered.
    hrr <- usingState_ ctx getTLS13HRR
    when hrr $ do
        mg <- usingHState ctx getSupportedGroup
        unless (map (Just . keyShareEntryGroup) keyShares == [mg]) $
            throwCore $
                Error_Protocol "key_share not for the group of hello retry" IllegalParameter
    -- RFC 9846 Section 4.2.8: servers MAY check this.
    unless (all ((`elem` allClientGroups) . keyShareEntryGroup) keyShares) $
        throwCore $
            Error_Protocol "key_share for a group not in supported_groups" IllegalParameter
    (mgroup, doHRR) <-
        onSelectKeyShare
            (serverHooks sparams)
            serverGroups
            clientGroups
            $ map keyShareEntryGroup keyShares
    keyshareResult <- case mgroup of
        Nothing -> return SelectKeyShareNotFound
        Just g
            | doHRR -> return $ SelectKeyShareHRR g
            | otherwise -> case filter (\e -> keyShareEntryGroup e == g) keyShares of
                [] -> return SelectKeyShareNotFound
                [x] -> return $ SelectKeyShareFound x
                _ -> throwCore $ Error_Protocol "duplicated key_share" IllegalParameter

    let triple = (usedCipher, usedHash, rtt0)
    pskEarlySecret <- pskAndEarlySecret sparams ctx triple ch
    (ich, b) <- fromJust <$> usingHState ctx getClientHello
    updateTranscriptHash12 ctx (ClientHello ich, b)
    return (keyshareResult, triple, pskEarlySecret)
  where
    ciphersFilteredVersion = intersectCiphers chCiphers serverCiphers
    serverCiphers =
        filter
            (cipherAllowedForVersion TLS13)
            (supportedCiphers $ serverSupported sparams)
    serverGroups = supportedGroupsTLS13 $ serverSupported sparams

data SelectKeyShareResult
    = -- | Negotiation failure
      SelectKeyShareNotFound
    | -- | Send a hello retry request with this group
      SelectKeyShareHRR Group
    | -- | Use this key share
      SelectKeyShareFound KeyShareEntry
    deriving (Eq, Show)

pskAndEarlySecret
    :: ServerParams
    -> Context
    -> (Cipher, Hash, Bool) -- rtt0
    -> ClientHello
    -> IO (SecretPair EarlySecret, [ExtensionRaw], Bool, Bool, Maybe ByteString)
    -- authenticated, is0RTTvalid, ticket ALPN
pskAndEarlySecret sparams ctx (usedCipher, usedHash, rtt0) CH{..} = do
    (psk, binderInfo, is0RTTvalid, ticketALPN) <- choosePSK
    earlyKey <- calculateEarlySecret ctx choice (Left psk)
    let earlySecret = pairBase earlyKey
        authenticated = isJust binderInfo
    preSharedKeyExt <- checkBinder earlySecret binderInfo
    return (earlyKey, preSharedKeyExt, authenticated, is0RTTvalid, ticketALPN)
  where
    choice = makeCipherChoice TLS13 usedCipher

    choosePSK =
        lookupAndDecodeAndDo
            EID_PreSharedKey
            MsgTClientHello
            chExtensions
            (return (zero, Nothing, False, Nothing))
            selectPSK

    selectPSK (PreSharedKeyClientHello ids bnds) = do
        when (null dhModes) $
            throwCore $
                Error_Protocol "no psk_key_exchange_modes extension" MissingExtension
        if PSK_DHE_KE `elem` dhModes
            then do
                let len = sum (map (\x -> B.length x + 1) bnds) + 2
                -- The first identity that can be resumed is chosen, each
                -- with its own age and binder.
                tryPSK len $ zip3 [0 ..] ids bnds
            else return (zero, Nothing, False, Nothing)
    selectPSK _ = return (zero, Nothing, False, Nothing)

    tryPSK _ [] = return (zero, Nothing, False, Nothing)
    tryPSK len ((n, PskIdentity identity obfAge, bnd) : rest) = do
        let mgr = sharedSessionManager $ serverShared sparams
        -- sessionInvalidate is not used for TLS 1.3
        -- because PSK is always changed.
        -- So, identity is not stored in Context.
        -- Early data is only with the first identity.
        msdata <-
            if rtt0 && n == 0
                then sessionResumeOnlyOnce mgr identity
                else sessionResume mgr identity
        case msdata of
            -- RFC 8446 Section 4.6.1: only a TLS 1.3 session, which
            -- has its ticket information, is resumed with a PSK.  A
            -- TLS 1.2 one found under the same identity falls back
            -- to a full handshake.
            Just sdata
                | sessionVersion sdata == TLS13
                , Just tinfo <- sessionTicketInfo sdata -> do
                    let psk = sessionSecret sdata
                    isFresh <- checkFreshness tinfo obfAge
                    (isPSKvalid, is0RTTvalid) <- checkSessionEquality sdata
                    if isPSKvalid && isFresh
                        then do
                            restoreClientCertificate ctx sdata
                            return
                                ( psk
                                , Just (bnd, n :: Int, len)
                                , is0RTTvalid && n == 0
                                , sessionALPN sdata
                                )
                        else tryPSK len rest
            _ -> tryPSK len rest

    checkBinder _ Nothing = return []
    checkBinder earlySecret (Just (binder, n, tlen)) = do
        (_, b) <- fromJust <$> usingHState ctx getClientHello
        binder' <- makePSKBinder ctx earlySecret usedHash tlen $ B.concat b
        unless (binder == binder') $
            decryptError "PSK binder validation failed"
        return [toExtensionRaw $ PreSharedKeyServerHello $ fromIntegral n]

    checkSessionEquality sdata = do
        msni <- usingState_ ctx getClientSNI
        let isSameSNI = sessionClientSNI sdata == msni
            isSameCipher = sessionCipher sdata == cipherID usedCipher
            ciphers = supportedCiphers $ serverSupported sparams
            scid = sessionCipher sdata
            isSameKDF = case findCipher scid ciphers of
                Nothing -> False
                Just c -> cipherHash c == cipherHash usedCipher
            isSameVersion = TLS13 == sessionVersion sdata
            isPSKvalid = isSameKDF && isSameSNI -- fixme: SNI is not required
            is0RTTvalid = isSameVersion && isSameCipher
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
