{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Concurrent
import Control.Concurrent.Async
import qualified Control.Exception as E
import Control.Monad (unless, forever)
import qualified Crypto.PubKey.RSA as RSA
import Crypto.Random
import Data.Default (def)
import Data.Hourglass
import Data.IORef
import Data.X509
import Data.X509.Validation
import GHC.Base (when)
import Gauge.Main
import Network.TLS hiding (HashSHA1, HashSHA256)
import Network.TLS.Extra.Cipher
import System.IO.Unsafe

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

blockCipher :: Cipher
blockCipher =
    Cipher
        { cipherID = 0xff12
        , cipherName = "rsa-id-const"
        , cipherBulk =
            Bulk
                { bulkName = "id"
                , bulkKeySize = 16
                , bulkIVSize = 16
                , bulkExplicitIV = 0
                , bulkAuthTagLen = 0
                , bulkBlockSize = 16
                , bulkF = BulkBlockF $ \_ _ _ m -> (m, B.empty)
                }
        , cipherHash = MD5
        , cipherPRFHash = Nothing
        , cipherKeyExchange = CipherKeyExchange_RSA
        , cipherMinVer = Nothing
        }

getParams :: Version -> Cipher -> (ClientParams, ServerParams)
getParams connectVer cipher = (cParams, sParams)
  where
    sParams =
        def
            { serverSupported = supported
            , serverShared =
                def
                    { sharedCredentials =
                        Credentials
                            [(CertificateChain [simpleX509 $ PubKeyRSA pubKey], PrivKeyRSA privKey)]
                    }
            }
    cParams =
        (defaultParamsClient "" B.empty)
            { clientSupported = supported
            , clientShared =
                def
                    { sharedValidationCache =
                        ValidationCache
                            { cacheAdd = \_ _ _ -> return ()
                            , cacheQuery = \_ _ _ -> return ValidationCachePass
                            }
                    }
            }
    supported =
        def
            { supportedCiphers = [cipher]
            , supportedVersions = [connectVer]
            , supportedGroups = [X25519, FFDHE2048]
            }
    (pubKey, privKey) = getGlobalRSAPair

runTLSPipe
    :: (ClientParams, ServerParams)
    -> (Context -> Chan b -> IO ())
    -> (Chan a -> Context -> IO ())
    -> a
    -> IO b
runTLSPipe params tlsServer tlsClient d = do
    withDataPipe params tlsServer tlsClient $ \(writeStart, readResult) -> do
        writeStart d
        readResult

runTLSPipeSimple
    :: (ClientParams, ServerParams) -> B.ByteString -> IO B.ByteString
runTLSPipeSimple params = runTLSPipe params tlsServer tlsClient
  where
    tlsServer ctx queue = do
        handshake ctx
        d <- recvData ctx
        writeChan queue d
        bye ctx
    tlsClient queue ctx = do
        handshake ctx
        d <- readChan queue
        sendData ctx (L.fromChunks [d])
        byeBye ctx

benchConnection
    :: (ClientParams, ServerParams) -> B.ByteString -> String -> Benchmark
benchConnection params !d name = bench name . nfIO $ runTLSPipeSimple params d

benchResumption
    :: (ClientParams, ServerParams) -> B.ByteString -> String -> Benchmark
benchResumption params !d name = env initializeSession runResumption
  where
    initializeSession = do
        sessionRefs <- twoSessionRefs
        let sessionManagers = twoSessionManagers sessionRefs
            params1 = setPairParamsSessionManagers sessionManagers params
        _ <- runTLSPipeSimple params1 d

        Just sessionParams <- readClientSessionRef sessionRefs
        let params2 = setPairParamsSessionResuming sessionParams params1
        newIORef params2

    runResumption paramsRef = bench name . nfIO $ do
        params2 <- readIORef paramsRef
        runTLSPipeSimple params2 d

benchResumption13
    :: (ClientParams, ServerParams) -> B.ByteString -> String -> Benchmark
benchResumption13 params !d name = env initializeSession runResumption
  where
    initializeSession = do
        sessionRefs <- twoSessionRefs
        let sessionManagers = twoSessionManagers sessionRefs
            params1 = setPairParamsSessionManagers sessionManagers params
        _ <- runTLSPipeSimple params1 d
        newIORef (params1, sessionRefs)

    -- with TLS13 the sessionId is constantly changing so we must update
    -- our parameters at each iteration unfortunately
    runResumption paramsRef = bench name . nfIO $ do
        (params1, sessionRefs) <- readIORef paramsRef
        Just sessionParams <- readClientSessionRef sessionRefs
        let params2 = setPairParamsSessionResuming sessionParams params1
        runTLSPipeSimple params2 d

benchCiphers :: String -> Version -> B.ByteString -> [Cipher] -> Benchmark
benchCiphers name connectVer d = bgroup name . map doBench
  where
    doBench cipher =
        benchResumption13 (getParams connectVer cipher) d (cipherName cipher)

main :: IO ()
main =
    defaultMain
        [ bgroup
            "connection"
            -- not sure the number actually make sense for anything. improve ..
            [
            --   benchConnection (getParams SSL3 blockCipher) small "SSL3-256 bytes",
            --   benchConnection (getParams TLS10 blockCipher) small "TLS10-256 bytes",
            --   benchConnection (getParams TLS11 blockCipher) small "TLS11-256 bytes",
              benchConnection (getParams TLS12 blockCipher) small "TLS12-256 bytes"
            ]
        , bgroup
            "resumption"
            [
                -- benchResumption (getParams SSL3 blockCipher) small "SSL3-256 bytes",
                -- benchResumption (getParams TLS10 blockCipher) small "TLS10-256 bytes",
                -- benchResumption (getParams TLS11 blockCipher) small "TLS11-256 bytes",
                benchResumption (getParams TLS12 blockCipher) small "TLS12-256 bytes"
            ]
        , -- Here we try to measure TLS12 and TLS13 performance with AEAD ciphers.
          -- Resumption and a larger message can be a demonstration of the symmetric
          -- crypto but for TLS13 this does not work so well because of dhe_psk.
          benchCiphers
            "TLS12"
            TLS12
            large
            [ cipher_DHE_RSA_WITH_AES_128_GCM_SHA256
            , cipher_DHE_RSA_WITH_AES_256_GCM_SHA384
            , cipher_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            , cipher_ECDHE_ECDSA_WITH_AES_128_CCM
            , cipher_ECDHE_ECDSA_WITH_AES_128_CCM_8
            , cipher_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            , cipher_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            , cipher_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            ]
        , benchCiphers
            "TLS13"
            TLS13
            large
            [ cipher13_AES_128_GCM_SHA256
            , cipher13_AES_256_GCM_SHA384
            , cipher13_CHACHA20_POLY1305_SHA256
            , cipher13_AES_128_CCM_SHA256
            , cipher13_AES_128_CCM_8_SHA256
            ]
        ]
  where
    small = B.replicate 256 0
    large = B.replicate 102400 0

withDataPipe :: (ClientParams, ServerParams) -> (Context -> Chan result -> IO ()) -> (Chan start -> Context -> IO ()) -> ((start -> IO (), IO result) -> IO a) -> IO a
withDataPipe params tlsServer tlsClient cont = do
    -- initial setup
    startQueue  <- newChan
    resultQueue <- newChan

    (cCtx, sCtx) <- newPairContext params

    withAsync (E.catch (tlsServer sCtx resultQueue)
                       (printAndRaise "server" (serverSupported $ snd params))) $ \sAsync -> withAsync (E.catch (tlsClient startQueue cCtx)
                                (printAndRaise "client" (clientSupported $ fst params))) $ \cAsync -> do
      let readResult = waitBoth cAsync sAsync >> readChan resultQueue
      cont (writeChan startQueue, readResult)

  where
        printAndRaise :: String -> Supported -> E.SomeException -> IO ()
        printAndRaise s supported e = do
            putStrLn $ s ++ " exception: " ++ show e ++
                            ", supported: " ++ show supported
            E.throwIO e

simpleX509 :: PubKey -> SignedCertificate
simpleX509 pubKey =
    let cert = simpleCertificate pubKey
        sig = replicate 40 1
        sigalg = getSignatureALG pubKey
        (signedExact, ()) = objectToSignedExact (\_ -> (B.pack sig, sigalg, ())) cert
     in signedExact

simpleCertificate :: PubKey -> Certificate
simpleCertificate pubKey =
    Certificate
        { certVersion = 3
        , certSerial = 0
        , certSignatureAlg = getSignatureALG pubKey
        , certIssuerDN = simpleDN
        , certSubjectDN = simpleDN
        , certValidity = (time1, time2)
        , certPubKey = pubKey
        , certExtensions =
            Extensions $
                Just
                    [ extensionEncode True $
                        ExtKeyUsage [KeyUsage_digitalSignature, KeyUsage_keyEncipherment]
                    ]
        }
  where
    time1 = DateTime (Date 1999 January 1) (TimeOfDay 0 0 0 0)
    time2 = DateTime (Date 2049 January 1) (TimeOfDay 0 0 0 0)
    simpleDN = DistinguishedName []

-- Terminate the write direction and wait to receive the peer EOF.  This is
-- necessary in situations where we want to confirm the peer status, or to make
-- sure to receive late messages like session tickets.  In the test suite this
-- is used each time application code ends the connection without prior call to
-- 'recvData'.
byeBye :: Context -> IO ()
byeBye ctx = do
    bye ctx
    bs <- recvData ctx
    unless (B.null bs) $ fail "byeBye: unexpected application data"



---------------------------------------------------------------------------------
{-
  Copy-paste from tls tests
-}

---------------------------------------------------------------------------------

getSignatureALG :: PubKey -> SignatureALG
getSignatureALG (PubKeyRSA _) = SignatureALG HashSHA1 PubKeyALG_RSA
getSignatureALG (PubKeyDSA _) = SignatureALG HashSHA1 PubKeyALG_DSA
getSignatureALG (PubKeyEC _) = SignatureALG HashSHA256 PubKeyALG_EC
getSignatureALG (PubKeyEd25519 _) = SignatureALG_IntrinsicHash PubKeyALG_Ed25519
getSignatureALG (PubKeyEd448 _) = SignatureALG_IntrinsicHash PubKeyALG_Ed448
getSignatureALG pubKey = error $ "getSignatureALG: unsupported public key: " ++ show pubKey

readClientSessionRef :: (IORef (Maybe c), IORef (Maybe s)) -> IO (Maybe c)
readClientSessionRef refs = readIORef (fst refs)

clearClientSessionRef :: (IORef (Maybe c), IORef (Maybe s)) -> IO ()
clearClientSessionRef refs = writeIORef (fst refs) Nothing

twoSessionRefs :: IO (IORef (Maybe client), IORef (Maybe server))
twoSessionRefs = (,) <$> newIORef Nothing <*> newIORef Nothing


setPairParamsSessionResuming
    :: (SessionID, SessionData)
    -> (ClientParams, ServerParams)
    -> (ClientParams, ServerParams)
setPairParamsSessionResuming sessionStuff (clientParams, serverParams) =
    ( clientParams{clientWantSessionResume = Just sessionStuff}
    , serverParams
    )

setPairParamsSessionManagers
    :: (SessionManager, SessionManager)
    -> (ClientParams, ServerParams)
    -> (ClientParams, ServerParams)
setPairParamsSessionManagers (clientManager, serverManager) (clientParams, serverParams) = (nc, ns)
  where
    nc =
        clientParams
            { clientShared = updateSessionManager clientManager $ clientShared clientParams
            }
    ns =
        serverParams
            { serverShared = updateSessionManager serverManager $ serverShared serverParams
            }
    updateSessionManager manager shared = shared{sharedSessionManager = manager}


twoSessionManagers
    :: (IORef (Maybe (SessionID, SessionData)), IORef (Maybe (SessionID, SessionData)))
    -> (SessionManager, SessionManager)
twoSessionManagers (cRef, sRef) = (oneSessionManager cRef, oneSessionManager sRef)

-- | simple session manager to store one session id and session data for a single thread.
-- a Real concurrent session manager would use an MVar and have multiples items.
oneSessionManager :: IORef (Maybe (SessionID, SessionData)) -> SessionManager
oneSessionManager ref =
    noSessionManager
        { sessionResume = \myId -> readIORef ref >>= maybeResume False myId
        , sessionResumeOnlyOnce = \myId -> readIORef ref >>= maybeResume True myId
        , sessionEstablish = \myId dat -> writeIORef ref (Just (myId, dat)) >> return Nothing
        , sessionInvalidate = \_ -> return ()
        , sessionUseTicket = False
        }
  where
    maybeResume onlyOnce myId (Just (sid, sdata))
        | sid == myId = when onlyOnce (writeIORef ref Nothing) >> return (Just sdata)
    maybeResume _ _ _ = return Nothing


{-# NOINLINE getGlobalRSAPair #-}
getGlobalRSAPair :: (RSA.PublicKey, RSA.PrivateKey)
getGlobalRSAPair = unsafePerformIO (readMVar globalRSAPair)

{-# NOINLINE globalRSAPair #-}
globalRSAPair :: MVar (RSA.PublicKey, RSA.PrivateKey)
globalRSAPair = unsafePerformIO $ do
    drg <- drgNew
    newMVar (fst $ withDRG drg arbitraryRSAPairWithRNG)

arbitraryRSAPairWithRNG :: MonadRandom m => m (RSA.PublicKey, RSA.PrivateKey)
arbitraryRSAPairWithRNG = RSA.generate 256 0x10001

-- | represent a unidirectional pipe with a buffered read channel and
-- a write channel
data UniPipeChan = UniPipeChan
    { getReadUniPipe :: Chan B.ByteString
    , getWriteUniPipe :: Chan B.ByteString
    }

newUniPipeChan :: IO UniPipeChan
newUniPipeChan = UniPipeChan <$> newChan <*> newChan

runUniPipe :: UniPipeChan -> IO ThreadId
runUniPipe UniPipeChan{..} =
    forkIO $
        forever $
            readChan getReadUniPipe >>= writeChan getWriteUniPipe

----------------------------------------------------------------

-- | Represent a bidirectional pipe with 2 nodes A and B
data PipeChan = PipeChan
    { fromC :: IORef B.ByteString
    , fromS :: IORef B.ByteString
    , c2s :: UniPipeChan
    , s2c :: UniPipeChan
    }

newPipe :: IO PipeChan
newPipe =
    PipeChan
        <$> newIORef B.empty
        <*> newIORef B.empty
        <*> newUniPipeChan
        <*> newUniPipeChan

runPipe :: PipeChan -> IO (ThreadId, ThreadId)
runPipe PipeChan{..} = (,) <$> runUniPipe c2s <*> runUniPipe s2c

readPipeC :: PipeChan -> Int -> IO B.ByteString
readPipeC PipeChan{..} sz = readBuffered fromS (getWriteUniPipe s2c) sz

writePipeC :: PipeChan -> B.ByteString -> IO ()
writePipeC PipeChan{..} = writeChan $ getWriteUniPipe c2s

readPipeS :: PipeChan -> Int -> IO B.ByteString
readPipeS PipeChan{..} sz = readBuffered fromC (getWriteUniPipe c2s) sz

writePipeS :: PipeChan -> B.ByteString -> IO ()
writePipeS PipeChan{..} = writeChan $ getReadUniPipe s2c

-- helper to read buffered data.
readBuffered :: IORef B.ByteString -> Chan B.ByteString -> Int -> IO B.ByteString
readBuffered ref chan sz = do
    left <- readIORef ref
    if B.length left >= sz
        then do
            let (ret, nleft) = B.splitAt sz left
            writeIORef ref nleft
            return ret
        else do
            let newSize = sz - B.length left
            newData <- readChan chan
            writeIORef ref newData
            remain <- readBuffered ref chan newSize
            return (left `B.append` remain)


newPairContext
    :: (ClientParams, ServerParams)
    -> IO (Context, Context)
newPairContext (cParams, sParams) = do
    pipe <- newPipe
    _tids <- runPipe pipe
    let noFlush = return ()
    let noClose = return ()

    let cBackend = Backend noFlush noClose (writePipeC pipe) (readPipeC pipe)
    let sBackend = Backend noFlush noClose (writePipeS pipe) (readPipeS pipe)
    cCtx' <- contextNew cBackend cParams
    sCtx' <- contextNew sBackend sParams

    contextHookSetLogging cCtx' (logging "client: ")
    contextHookSetLogging sCtx' (logging "server: ")

    return ((cCtx', sCtx'))
  where
    debug :: Bool
    debug = False
    logging pre =
        if debug
            then
                defaultLogging
                    { loggingPacketSent = putStrLn . ((pre ++ ">> ") ++)
                    , loggingPacketRecv = putStrLn . ((pre ++ "<< ") ++)
                    }
            else defaultLogging
