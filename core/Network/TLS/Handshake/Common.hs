{-# LANGUAGE OverloadedStrings #-}
module Network.TLS.Handshake.Common
    ( handshakeFailed
    , errorToAlert
    , unexpected
    , newSession
    , handshakeTerminate
    -- * sending packets
    , sendChangeCipherAndFinish
    -- * receiving packets
    , recvChangeCipherAndFinish
    , RecvState(..)
    , runRecvState
    , recvPacketHandshake
    , onRecvStateHandshake
    , extensionLookup
    , getSessionData
    , storePrivInfo
    ) where

import Control.Concurrent.MVar

import Network.TLS.Parameters
import Network.TLS.Compression
import Network.TLS.Context.Internal
import Network.TLS.Session
import Network.TLS.Struct
import Network.TLS.IO
import Network.TLS.State
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.State
import Network.TLS.Record.State
import Network.TLS.Measurement
import Network.TLS.Types
import Network.TLS.Cipher
import Network.TLS.Crypto
import Network.TLS.Util
import Network.TLS.X509
import Network.TLS.Imports

import Control.Monad.State.Strict
import Control.Exception (throwIO)

handshakeFailed :: TLSError -> IO ()
handshakeFailed err = throwIO $ HandshakeFailed err

errorToAlert :: TLSError -> [(AlertLevel, AlertDescription)]
errorToAlert (Error_Protocol (_, _, ad)) = [(AlertLevel_Fatal, ad)]
errorToAlert _                           = [(AlertLevel_Fatal, InternalError)]

unexpected :: MonadIO m => String -> Maybe String -> m a
unexpected msg expected = throwCore $ Error_Packet_unexpected msg (maybe "" (" expected: " ++) expected)

newSession :: Context -> IO Session
newSession ctx
    | supportedSession $ ctxSupported ctx = Session . Just <$> getStateRNG ctx 32
    | otherwise                           = return $ Session Nothing

-- | when a new handshake is done, wrap up & clean up.
handshakeTerminate :: Context -> IO ()
handshakeTerminate ctx = do
    session <- usingState_ ctx getSession
    -- only callback the session established if we have a session
    case session of
        Session (Just sessionId) -> do
            sessionData <- getSessionData ctx
            liftIO $ sessionEstablish (sharedSessionManager $ ctxShared ctx) sessionId (fromJust "session-data" sessionData)
        _ -> return ()
    -- forget most handshake data and reset bytes counters.
    liftIO $ modifyMVar_ (ctxHandshake ctx) $ \ mhshake ->
        case mhshake of
            Nothing -> return Nothing
            Just hshake ->
                return $ Just (newEmptyHandshake (hstClientVersion hshake) (hstClientRandom hshake))
                    { hstServerRandom = hstServerRandom hshake
                    , hstMasterSecret = hstMasterSecret hshake
                    , hstNegotiatedGroup = hstNegotiatedGroup hshake
                    }
    updateMeasure ctx resetBytesCounters
    -- mark the secure connection up and running.
    setEstablished ctx Established
    return ()

sendChangeCipherAndFinish :: Context
                          -> Role
                          -> IO ()
sendChangeCipherAndFinish ctx role = do
    sendPacket ctx ChangeCipherSpec
    liftIO $ contextFlush ctx
    cf <- usingState_ ctx getVersion >>= \ver -> usingHState ctx $ getHandshakeDigest ver role
    sendPacket ctx (Handshake [Finished cf])
    liftIO $ contextFlush ctx

recvChangeCipherAndFinish :: Context -> IO ()
recvChangeCipherAndFinish ctx = runRecvState ctx (RecvStateNext expectChangeCipher)
  where expectChangeCipher ChangeCipherSpec = return $ RecvStateHandshake expectFinish
        expectChangeCipher p                = unexpected (show p) (Just "change cipher")
        expectFinish (Finished _) = return RecvStateDone
        expectFinish p            = unexpected (show p) (Just "Handshake Finished")

data RecvState m =
      RecvStateNext (Packet -> m (RecvState m))
    | RecvStateHandshake (Handshake -> m (RecvState m))
    | RecvStateDone

recvPacketHandshake :: Context -> IO [Handshake]
recvPacketHandshake ctx = do
    pkts <- recvPacket ctx
    case pkts of
        Right (Handshake l) -> return l
        Right x             -> fail ("unexpected type received. expecting handshake and got: " ++ show x)
        Left err            -> throwCore err

-- | process a list of handshakes message in the recv state machine.
onRecvStateHandshake :: Context -> RecvState IO -> [Handshake] -> IO (RecvState IO)
onRecvStateHandshake _   recvState [] = return recvState
onRecvStateHandshake ctx (RecvStateHandshake f) (x:xs) = do
    nstate <- f x
    processHandshake ctx x
    onRecvStateHandshake ctx nstate xs
onRecvStateHandshake _ _ _   = unexpected "spurious handshake" Nothing

runRecvState :: Context -> RecvState IO -> IO ()
runRecvState _    RecvStateDone    = return ()
runRecvState ctx (RecvStateNext f) = recvPacket ctx >>= either throwCore f >>= runRecvState ctx
runRecvState ctx iniState          = recvPacketHandshake ctx >>= onRecvStateHandshake ctx iniState >>= runRecvState ctx

getSessionData :: Context -> IO (Maybe SessionData)
getSessionData ctx = do
    ver <- usingState_ ctx getVersion
    sni <- usingState_ ctx getClientSNI
    mms <- usingHState ctx (gets hstMasterSecret)
    tx  <- liftIO $ readMVar (ctxTxState ctx)
    alpn <- usingState_ ctx getNegotiatedProtocol
    case mms of
        Nothing -> return Nothing
        Just ms -> return $ Just SessionData
                        { sessionVersion     = ver
                        , sessionCipher      = cipherID $ fromJust "cipher" $ stCipher tx
                        , sessionCompression = compressionID $ stCompression tx
                        , sessionClientSNI   = sni
                        , sessionSecret      = ms
                        , sessionGroup       = Nothing
                        , sessionTicketInfo  = Nothing
                        , sessionALPN        = alpn
                        , sessionMaxEarlyDataSize = 0
                        }

extensionLookup :: ExtensionID -> [ExtensionRaw] -> Maybe ByteString
extensionLookup toFind = fmap (\(ExtensionRaw _ content) -> content)
                       . find (\(ExtensionRaw eid _) -> eid == toFind)

-- | Store private key and associated DigitalSignatureAlg, optionally
-- checking the keypair is compatible with a list of 'CertificateType'
-- values.
--
storePrivInfo :: Context
              -> Maybe [CertificateType]
              -> CertificateChain
              -> PrivKey
              -> IO ()
storePrivInfo ctx cTypes cc privkey = do
    let (CertificateChain (c:_)) = cc
        pubkey = certPubKey $ getCertificate c
        -- FIXME: Add ECDSA with at least the P-256, P-384
        -- and P-521 curves.  Also Ed25519 and Ed448.
        --
        -- FIXME: The 'rsaok', 'dsaok' tests need a better
        -- abstraction.
        --
        dsaok = any (== CertificateType_DSS_Sign) <$> cTypes
        rsaok = any (== CertificateType_RSA_Sign) <$> cTypes
    privalg <- case findDigitalSignatureAlg (pubkey, privkey) of
        Just RSA | rsaok /= Just False
                -> return RSA
        Just DSS | dsaok /= Just False
                -> return DSS
        _       -> throwCore $ Error_Protocol
                       ( keyerr
                       , True
                       , InternalError )
    -- XXX: Whether the public key and private key actually
    -- match is left for the peer to discover.  We're not
    -- presently burning CPU to detect that misconfiguration.
    --
    usingHState ctx $ setPrivateKey privkey privalg
  where
    keyerr = "mismatched or unsupported private key pair"
