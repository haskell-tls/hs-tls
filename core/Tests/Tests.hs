{-# LANGUAGE OverloadedStrings #-}

import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck.Monadic

import PipeChan
import Connection
import Marshalling
import Ciphers
import PubKey

import Data.Foldable (traverse_)
import Data.Maybe
import Data.Default.Class
import Data.List (intersect)

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as L
import Network.TLS
import Network.TLS.Extra
import Network.TLS.Internal
import Control.Applicative
import Control.Concurrent
import Control.Concurrent.Async
import Control.Monad

import Data.IORef
import Data.X509 (ExtKeyUsageFlag(..))

import System.Timeout

prop_pipe_work :: PropertyM IO ()
prop_pipe_work = do
    pipe <- run newPipe
    _ <- run (runPipe pipe)

    let bSize = 16
    n <- pick (choose (1, 32))

    let d1 = B.replicate (bSize * n) 40
    let d2 = B.replicate (bSize * n) 45

    d1' <- run (writePipeA pipe d1 >> readPipeB pipe (B.length d1))
    d1 `assertEq` d1'

    d2' <- run (writePipeB pipe d2 >> readPipeA pipe (B.length d2))
    d2 `assertEq` d2'

    return ()

chunkLengths :: Int -> [Int]
chunkLengths len
    | len > 16384 = 16384 : chunkLengths (len - 16384)
    | len > 0     = [len]
    | otherwise   = []

runTLSPipeN :: Int -> (ClientParams, ServerParams) -> (Context -> Chan [C8.ByteString] -> IO ()) -> (Chan C8.ByteString -> Context -> IO ()) -> PropertyM IO ()
runTLSPipeN n params tlsServer tlsClient = do
    -- generate some data to send
    ds <- replicateM n $ do
        d <- B.pack <$> pick (someWords8 256)
        return d
    -- send it
    m_dsres <- run $ do
        withDataPipe params tlsServer tlsClient $ \(writeStart, readResult) -> do
            forM_ ds $ \d -> do
                writeStart d
            -- receive it
            timeout 60000000 readResult -- 60 sec
    case m_dsres of
        Nothing -> error "timed out"
        Just dsres -> ds `assertEq` dsres

runTLSPipe :: (ClientParams, ServerParams) -> (Context -> Chan [C8.ByteString] -> IO ()) -> (Chan C8.ByteString -> Context -> IO ()) -> PropertyM IO ()
runTLSPipe = runTLSPipeN 1

runTLSPipePredicate :: (ClientParams, ServerParams) -> (Maybe Information -> Bool) -> PropertyM IO ()
runTLSPipePredicate params p = runTLSPipe params tlsServer tlsClient
  where tlsServer ctx queue = do
            handshake ctx
            checkInfoPredicate ctx
            d <- recvData ctx
            writeChan queue [d]
            bye ctx
        tlsClient queue ctx = do
            handshake ctx
            checkInfoPredicate ctx
            d <- readChan queue
            sendData ctx (L.fromChunks [d])
            byeBye ctx
        checkInfoPredicate ctx = do
            minfo <- contextGetInformation ctx
            unless (p minfo) $
                fail ("unexpected information: " ++ show minfo)

runTLSPipeSimple :: (ClientParams, ServerParams) -> PropertyM IO ()
runTLSPipeSimple params = runTLSPipePredicate params (const True)

runTLSPipeSimple13 :: (ClientParams, ServerParams) -> HandshakeMode13 -> Maybe C8.ByteString -> PropertyM IO ()
runTLSPipeSimple13 params mode mEarlyData = runTLSPipe params tlsServer tlsClient
  where tlsServer ctx queue = do
            handshake ctx
            case mEarlyData of
                Nothing -> return ()
                Just ed -> do
                    let ls = chunkLengths (B.length ed)
                    chunks <- replicateM (length ls) $ recvData ctx
                    (ls, ed) `assertEq` (map B.length chunks, B.concat chunks)
            d <- recvData ctx
            writeChan queue [d]
            minfo <- contextGetInformation ctx
            Just mode `assertEq` (minfo >>= infoTLS13HandshakeMode)
            bye ctx
        tlsClient queue ctx = do
            handshake ctx
            d <- readChan queue
            sendData ctx (L.fromChunks [d])
            minfo <- contextGetInformation ctx
            Just mode `assertEq` (minfo >>= infoTLS13HandshakeMode)
            byeBye ctx

runTLSPipeCapture13 :: (ClientParams, ServerParams) -> PropertyM IO ([Handshake13], [Handshake13])
runTLSPipeCapture13 params = do
    sRef <- run $ newIORef []
    cRef <- run $ newIORef []
    runTLSPipe params (tlsServer sRef) (tlsClient cRef)
    sReceived <- run $ readIORef sRef
    cReceived <- run $ readIORef cRef
    return (reverse sReceived, reverse cReceived)
  where tlsServer ref ctx queue = do
            installHook ctx ref
            handshake ctx
            d <- recvData ctx
            writeChan queue [d]
            bye ctx
        tlsClient ref queue ctx = do
            installHook ctx ref
            handshake ctx
            d <- readChan queue
            sendData ctx (L.fromChunks [d])
            byeBye ctx
        installHook ctx ref =
            let recv hss = modifyIORef ref (hss :) >> return hss
             in contextHookSetHandshake13Recv ctx recv

runTLSPipeSimpleKeyUpdate :: (ClientParams, ServerParams) -> PropertyM IO ()
runTLSPipeSimpleKeyUpdate params = runTLSPipeN 3 params tlsServer tlsClient
  where tlsServer ctx queue = do
            handshake ctx
            d0 <- recvData ctx
            req <- generate $ elements [OneWay, TwoWay]
            _ <- updateKey ctx req
            d1 <- recvData ctx
            d2 <- recvData ctx
            writeChan queue [d0,d1,d2]
            bye ctx
        tlsClient queue ctx = do
            handshake ctx
            d0 <- readChan queue
            sendData ctx (L.fromChunks [d0])
            d1 <- readChan queue
            sendData ctx (L.fromChunks [d1])
            req <- generate $ elements [OneWay, TwoWay]
            _ <- updateKey ctx req
            d2 <- readChan queue
            sendData ctx (L.fromChunks [d2])
            byeBye ctx

runTLSInitFailureGen :: (ClientParams, ServerParams) -> (Context -> IO s) -> (Context -> IO c) -> PropertyM IO ()
runTLSInitFailureGen params hsServer hsClient = do
    (cRes, sRes) <- run (initiateDataPipe params tlsServer tlsClient)
    assertIsLeft cRes
    assertIsLeft sRes
  where tlsServer ctx = do
            _ <- hsServer ctx
            minfo <- contextGetInformation ctx
            byeBye ctx
            return $ "server success: " ++ show minfo
        tlsClient ctx = do
            _ <- hsClient ctx
            minfo <- contextGetInformation ctx
            byeBye ctx
            return $ "client success: " ++ show minfo

runTLSInitFailure :: (ClientParams, ServerParams) -> PropertyM IO ()
runTLSInitFailure params = runTLSInitFailureGen params handshake handshake

prop_handshake_initiate :: PropertyM IO ()
prop_handshake_initiate = do
    params  <- pick arbitraryPairParams
    runTLSPipeSimple params

prop_handshake13_initiate :: PropertyM IO ()
prop_handshake13_initiate = do
    params  <- pick arbitraryPairParams13
    let cgrps = supportedGroups $ clientSupported $ fst params
        sgrps = supportedGroups $ serverSupported $ snd params
        hs = if head cgrps `elem` sgrps then FullHandshake else HelloRetryRequest
    runTLSPipeSimple13 params hs Nothing

prop_handshake_keyupdate :: PropertyM IO ()
prop_handshake_keyupdate = do
    params <- pick arbitraryPairParams
    runTLSPipeSimpleKeyUpdate params

prop_handshake13_downgrade :: PropertyM IO ()
prop_handshake13_downgrade = do
    (cparam,sparam) <- pick arbitraryPairParams
    versionForced <- pick $ elements (supportedVersions $ clientSupported cparam)
    let debug' = (serverDebug sparam) { debugVersionForced = Just versionForced }
        sparam' = sparam { serverDebug = debug' }
        params = (cparam,sparam')
        downgraded = (isVersionEnabled TLS13 params && versionForced < TLS13) ||
                     (isVersionEnabled TLS12 params && versionForced < TLS12)
    if downgraded
        then runTLSInitFailure params
        else runTLSPipeSimple params

prop_handshake13_full :: PropertyM IO ()
prop_handshake13_full = do
    (cli, srv) <- pick arbitraryPairParams13
    let cliSupported = def
          { supportedCiphers = [cipher_TLS13_AES128GCM_SHA256]
          , supportedGroups = [X25519]
          }
        svrSupported = def
          { supportedCiphers = [cipher_TLS13_AES128GCM_SHA256]
          , supportedGroups = [X25519]
          }
        params = (cli { clientSupported = cliSupported }
                 ,srv { serverSupported = svrSupported }
                 )
    runTLSPipeSimple13 params FullHandshake Nothing

prop_handshake13_hrr :: PropertyM IO ()
prop_handshake13_hrr = do
    (cli, srv) <- pick arbitraryPairParams13
    let cliSupported = def
          { supportedCiphers = [cipher_TLS13_AES128GCM_SHA256]
          , supportedGroups = [P256,X25519]
          }
        svrSupported = def
          { supportedCiphers = [cipher_TLS13_AES128GCM_SHA256]
          , supportedGroups = [X25519]
          }
        params = (cli { clientSupported = cliSupported }
                 ,srv { serverSupported = svrSupported }
                 )
    runTLSPipeSimple13 params HelloRetryRequest Nothing

prop_handshake13_psk :: PropertyM IO ()
prop_handshake13_psk = do
    (cli, srv) <- pick arbitraryPairParams13
    let cliSupported = def
          { supportedCiphers = [cipher_TLS13_AES128GCM_SHA256]
          , supportedGroups = [P256,X25519]
          }
        svrSupported = def
          { supportedCiphers = [cipher_TLS13_AES128GCM_SHA256]
          , supportedGroups = [X25519]
          }
        params0 = (cli { clientSupported = cliSupported }
                  ,srv { serverSupported = svrSupported }
                  )

    sessionRefs <- run twoSessionRefs
    let sessionManagers = twoSessionManagers sessionRefs

    let params = setPairParamsSessionManagers sessionManagers params0

    runTLSPipeSimple13 params HelloRetryRequest Nothing

    -- and resume
    sessionParams <- run $ readClientSessionRef sessionRefs
    assert (isJust sessionParams)
    let params2 = setPairParamsSessionResuming (fromJust sessionParams) params

    runTLSPipeSimple13 params2 PreSharedKey Nothing

prop_handshake13_psk_fallback :: PropertyM IO ()
prop_handshake13_psk_fallback = do
    (cli, srv) <- pick arbitraryPairParams13
    let cliSupported = def
            { supportedCiphers = [ cipher_TLS13_AES128GCM_SHA256
                                 , cipher_TLS13_AES128CCM_SHA256
                                 ]
            , supportedGroups = [P256,X25519]
            }
        svrSupported = def
            { supportedCiphers = [cipher_TLS13_AES128GCM_SHA256]
            , supportedGroups = [X25519]
            }
        params0 = (cli { clientSupported = cliSupported }
                  ,srv { serverSupported = svrSupported }
                  )

    sessionRefs <- run twoSessionRefs
    let sessionManagers = twoSessionManagers sessionRefs

    let params = setPairParamsSessionManagers sessionManagers params0

    runTLSPipeSimple13 params HelloRetryRequest Nothing

    -- resumption fails because GCM cipher is not supported anymore, full
    -- handshake is not possible because X25519 has been removed, so we are
    -- back with P256 after hello retry
    sessionParams <- run $ readClientSessionRef sessionRefs
    assert (isJust sessionParams)
    let (cli2, srv2) = setPairParamsSessionResuming (fromJust sessionParams) params
        srv2' = srv2 { serverSupported = svrSupported' }
        svrSupported' = def
            { supportedCiphers = [cipher_TLS13_AES128CCM_SHA256]
            , supportedGroups = [P256]
            }

    runTLSPipeSimple13 (cli2, srv2') HelloRetryRequest Nothing

prop_handshake13_rtt0 :: PropertyM IO ()
prop_handshake13_rtt0 = do
    (cli, srv) <- pick arbitraryPairParams13
    let cliSupported = def
          { supportedCiphers = [cipher_TLS13_AES128GCM_SHA256]
          , supportedGroups = [P256,X25519]
          }
        svrSupported = def
          { supportedCiphers = [cipher_TLS13_AES128GCM_SHA256]
          , supportedGroups = [X25519]
          }
        cliHooks = def {
            onSuggestALPN = return $ Just ["h2"]
          }
        svrHooks = def {
            onALPNClientSuggest = Just (\protos -> return $ head protos)
          }
        params0 = (cli { clientSupported = cliSupported
                       , clientHooks = cliHooks
                       }
                  ,srv { serverSupported = svrSupported
                       , serverHooks = svrHooks
                       , serverEarlyDataSize = 2048 }
                  )

    sessionRefs <- run twoSessionRefs
    let sessionManagers = twoSessionManagers sessionRefs

    let params = setPairParamsSessionManagers sessionManagers params0

    runTLSPipeSimple13 params HelloRetryRequest Nothing

    -- and resume
    sessionParams <- run $ readClientSessionRef sessionRefs
    assert (isJust sessionParams)
    earlyData <- B.pack <$> pick (someWords8 256)
    let (pc,ps) = setPairParamsSessionResuming (fromJust sessionParams) params
        params2 = (pc { clientEarlyData = Just earlyData } , ps)

    runTLSPipeSimple13 params2 RTT0 (Just earlyData)

prop_handshake13_rtt0_fallback :: PropertyM IO ()
prop_handshake13_rtt0_fallback = do
    ticketSize <- pick $ choose (0, 512)
    (cli, srv) <- pick arbitraryPairParams13
    group0 <- pick $ elements [P256,X25519]
    let cliSupported = def
          { supportedCiphers = [cipher_TLS13_AES128GCM_SHA256]
          , supportedGroups = [P256,X25519]
          }
        svrSupported = def
          { supportedCiphers = [cipher_TLS13_AES128GCM_SHA256]
          , supportedGroups = [group0]
          }
        params0 = (cli { clientSupported = cliSupported }
                  ,srv { serverSupported = svrSupported
                       , serverEarlyDataSize = ticketSize }
                  )

    sessionRefs <- run twoSessionRefs
    let sessionManagers = twoSessionManagers sessionRefs

    let params = setPairParamsSessionManagers sessionManagers params0

    let mode = if group0 == P256 then FullHandshake else HelloRetryRequest
    runTLSPipeSimple13 params mode Nothing

    -- and resume
    sessionParams <- run $ readClientSessionRef sessionRefs
    assert (isJust sessionParams)
    earlyData <- B.pack <$> pick (someWords8 256)
    group2 <- pick $ elements [P256,X25519]
    let (pc,ps) = setPairParamsSessionResuming (fromJust sessionParams) params
        svrSupported2 = def
          { supportedCiphers = [cipher_TLS13_AES128GCM_SHA256]
          , supportedGroups = [group2]
          }
        params2 = (pc { clientEarlyData = Just earlyData }
                  ,ps { serverEarlyDataSize = 0
                      , serverSupported = svrSupported2
                      }
                  )

    let mode2 = if ticketSize < 256 then PreSharedKey else RTT0
    runTLSPipeSimple13 params2 mode2 Nothing

prop_handshake13_rtt0_length :: PropertyM IO ()
prop_handshake13_rtt0_length = do
    serverMax <- pick $ choose (0, 33792)
    (cli, srv) <- pick arbitraryPairParams13
    let cliSupported = def
          { supportedCiphers = [cipher_TLS13_AES128GCM_SHA256]
          , supportedGroups = [X25519]
          }
        svrSupported = def
          { supportedCiphers = [cipher_TLS13_AES128GCM_SHA256]
          , supportedGroups = [X25519]
          }
        params0 = (cli { clientSupported = cliSupported }
                  ,srv { serverSupported = svrSupported
                       , serverEarlyDataSize = serverMax }
                  )

    sessionRefs <- run twoSessionRefs
    let sessionManagers = twoSessionManagers sessionRefs
    let params = setPairParamsSessionManagers sessionManagers params0
    runTLSPipeSimple13 params FullHandshake Nothing

    -- and resume
    sessionParams <- run $ readClientSessionRef sessionRefs
    assert (isJust sessionParams)
    clientLen <- pick $ choose (0, 33792)
    earlyData <- B.pack <$> pick (someWords8 clientLen)
    let (pc,ps) = setPairParamsSessionResuming (fromJust sessionParams) params
        params2 = (pc { clientEarlyData = Just earlyData } , ps)
        (mode, mEarlyData)
            | clientLen > serverMax = (PreSharedKey, Nothing)
            | otherwise             = (RTT0, Just earlyData)
    runTLSPipeSimple13 params2 mode mEarlyData

prop_handshake13_ee_groups :: PropertyM IO ()
prop_handshake13_ee_groups = do
    (cli, srv) <- pick arbitraryPairParams13
    let cliSupported = (clientSupported cli) { supportedGroups = [P256,X25519] }
        svrSupported = (serverSupported srv) { supportedGroups = [X25519,P256] }
        params = (cli { clientSupported = cliSupported }
                 ,srv { serverSupported = svrSupported }
                 )
    (_, serverMessages) <- runTLSPipeCapture13 params
    let isNegotiatedGroups (ExtensionRaw eid _) = eid == 0xa
        eeMessagesHaveExt = [ any isNegotiatedGroups exts |
                              EncryptedExtensions13 exts <- serverMessages ]
    [True] `assertEq` eeMessagesHaveExt  -- one EE message with extension

prop_handshake_ciphersuites :: PropertyM IO ()
prop_handshake_ciphersuites = do
    tls13 <- pick arbitrary
    let version = if tls13 then TLS13 else TLS12
    clientCiphers <- pick arbitraryCiphers
    serverCiphers <- pick arbitraryCiphers
    (clientParam,serverParam) <- pick $ arbitraryPairParamsWithVersionsAndCiphers
                                            ([version], [version])
                                            (clientCiphers, serverCiphers)
    let adequate = cipherAllowedForVersion version
        shouldSucceed = any adequate (clientCiphers `intersect` serverCiphers)
    if shouldSucceed
        then runTLSPipeSimple  (clientParam,serverParam)
        else runTLSInitFailure (clientParam,serverParam)

prop_handshake_hashsignatures :: PropertyM IO ()
prop_handshake_hashsignatures = do
    tls13 <- pick arbitrary
    let version = if tls13 then TLS13 else TLS12
        ciphers = [ cipher_ECDHE_RSA_AES256GCM_SHA384
                  , cipher_ECDHE_ECDSA_AES256GCM_SHA384
                  , cipher_ECDHE_RSA_AES128CBC_SHA
                  , cipher_ECDHE_ECDSA_AES128CBC_SHA
                  , cipher_DHE_RSA_AES128_SHA1
                  , cipher_DHE_DSS_AES128_SHA1
                  , cipher_TLS13_AES128GCM_SHA256
                  ]
    (clientParam,serverParam) <- pick $ arbitraryPairParamsWithVersionsAndCiphers
                                            ([version], [version])
                                            (ciphers, ciphers)
    clientHashSigs <- pick $ arbitraryHashSignatures version
    serverHashSigs <- pick $ arbitraryHashSignatures version
    let clientParam' = clientParam { clientSupported = (clientSupported clientParam)
                                       { supportedHashSignatures = clientHashSigs }
                                   }
        serverParam' = serverParam { serverSupported = (serverSupported serverParam)
                                       { supportedHashSignatures = serverHashSigs }
                                   }
        commonHashSigs = clientHashSigs `intersect` serverHashSigs
        shouldFail
            | tls13     = all incompatibleWithDefaultCurve commonHashSigs
            | otherwise = null commonHashSigs
    if shouldFail
        then runTLSInitFailure (clientParam',serverParam')
        else runTLSPipeSimple  (clientParam',serverParam')
  where
    incompatibleWithDefaultCurve (h, SignatureECDSA) = h /= HashSHA256
    incompatibleWithDefaultCurve _                   = False

-- Tests ability to use or ignore client "signature_algorithms" extension when
-- choosing a server certificate.  Here peers allow DHE_RSA_AES128_SHA1 but
-- the server RSA certificate has a SHA-1 signature that the client does not
-- support.  Server may choose the DSA certificate only when cipher
-- DHE_DSS_AES128_SHA1 is allowed.  Otherwise it must fallback to the RSA
-- certificate.
prop_handshake_cert_fallback :: PropertyM IO ()
prop_handshake_cert_fallback = do
    let clientVersions = [TLS12]
        serverVersions = [TLS12]
        commonCiphers  = [ cipher_DHE_RSA_AES128_SHA1 ]
        otherCiphers   = [ cipher_ECDHE_RSA_AES256GCM_SHA384
                         , cipher_ECDHE_RSA_AES128CBC_SHA
                         , cipher_DHE_DSS_AES128_SHA1
                         ]
        hashSignatures = [ (HashSHA256, SignatureRSA), (HashSHA1, SignatureDSS) ]
    chainRef <- run $ newIORef Nothing
    clientCiphers <- pick $ sublistOf otherCiphers
    serverCiphers <- pick $ sublistOf otherCiphers
    (clientParam,serverParam) <- pick $ arbitraryPairParamsWithVersionsAndCiphers
                                            (clientVersions, serverVersions)
                                            (clientCiphers ++ commonCiphers, serverCiphers ++ commonCiphers)
    let clientParam' = clientParam { clientSupported = (clientSupported clientParam)
                                       { supportedHashSignatures = hashSignatures }
                                   , clientHooks = (clientHooks clientParam)
                                       { onServerCertificate = \_ _ _ chain ->
                                             writeIORef chainRef (Just chain) >> return [] }
                                   }
        dssDisallowed = cipher_DHE_DSS_AES128_SHA1 `notElem` clientCiphers
                            || cipher_DHE_DSS_AES128_SHA1 `notElem` serverCiphers
    runTLSPipeSimple (clientParam',serverParam)
    serverChain <- run $ readIORef chainRef
    dssDisallowed `assertEq` isLeafRSA serverChain

-- Same as above but testing with supportedHashSignatures directly instead of
-- ciphers, and thus allowing TLS13.  Peers accept RSA with SHA-256 but the
-- server RSA certificate has a SHA-1 signature.  When Ed25519 is allowed by
-- both client and server, the Ed25519 certificate is selected.  Otherwise the
-- server fallbacks to RSA.
--
-- Note: SHA-1 is supposed to be disallowed in X.509 signatures with TLS13
-- unless client advertises explicit support.  Currently this is not enforced by
-- the library, which is useful to test this scenario.  SHA-1 could be replaced
-- by another algorithm.
prop_handshake_cert_fallback_hs :: PropertyM IO ()
prop_handshake_cert_fallback_hs = do
    tls13 <- pick arbitrary
    let versions = if tls13 then [TLS13] else [TLS12]
        ciphers  = [ cipher_ECDHE_RSA_AES128GCM_SHA256
                   , cipher_ECDHE_ECDSA_AES128GCM_SHA256
                   , cipher_TLS13_AES128GCM_SHA256
                   ]
        commonHS = [ (HashSHA256, SignatureRSA)
                   , (HashIntrinsic, SignatureRSApssRSAeSHA256)
                   ]
        otherHS  = [ (HashIntrinsic, SignatureEd25519) ]
    chainRef <- run $ newIORef Nothing
    clientHS <- pick $ sublistOf otherHS
    serverHS <- pick $ sublistOf otherHS
    (clientParam,serverParam) <- pick $ arbitraryPairParamsWithVersionsAndCiphers
                                            (versions, versions)
                                            (ciphers, ciphers)
    let clientParam' = clientParam { clientSupported = (clientSupported clientParam)
                                       { supportedHashSignatures = commonHS ++ clientHS }
                                   , clientHooks = (clientHooks clientParam)
                                       { onServerCertificate = \_ _ _ chain ->
                                             writeIORef chainRef (Just chain) >> return [] }
                                   }
        serverParam' = serverParam { serverSupported = (serverSupported serverParam)
                                       { supportedHashSignatures = commonHS ++ serverHS }
                                   }
        eddsaDisallowed = (HashIntrinsic, SignatureEd25519) `notElem` clientHS
                              || (HashIntrinsic, SignatureEd25519) `notElem` serverHS
    runTLSPipeSimple (clientParam',serverParam')
    serverChain <- run $ readIORef chainRef
    eddsaDisallowed `assertEq` isLeafRSA serverChain

prop_handshake_groups :: PropertyM IO ()
prop_handshake_groups = do
    tls13 <- pick arbitrary
    let versions = if tls13 then [TLS13] else [TLS12]
        ciphers = [ cipher_ECDHE_RSA_AES256GCM_SHA384
                  , cipher_ECDHE_RSA_AES128CBC_SHA
                  , cipher_DHE_RSA_AES256GCM_SHA384
                  , cipher_DHE_RSA_AES128_SHA1
                  , cipher_TLS13_AES128GCM_SHA256
                  ]
    (clientParam,serverParam) <- pick $ arbitraryPairParamsWithVersionsAndCiphers
                                            (versions, versions)
                                            (ciphers, ciphers)
    clientGroups <- pick arbitraryGroups
    serverGroups <- pick arbitraryGroups
    denyCustom   <- pick arbitrary
    let groupUsage = if denyCustom then GroupUsageUnsupported "custom group denied" else GroupUsageValid
        clientParam' = clientParam { clientSupported = (clientSupported clientParam)
                                       { supportedGroups = clientGroups }
                                   , clientHooks = (clientHooks clientParam)
                                       { onCustomFFDHEGroup = \_ _ -> return groupUsage }
                                   }
        serverParam' = serverParam { serverSupported = (serverSupported serverParam)
                                       { supportedGroups = serverGroups }
                                   }
        isCustom = maybe True isCustomDHParams (serverDHEParams serverParam')
        mCustomGroup = serverDHEParams serverParam' >>= dhParamsGroup
        isClientCustom = maybe True (`notElem` clientGroups) mCustomGroup
        commonGroups = clientGroups `intersect` serverGroups
        shouldFail = null commonGroups && (tls13 || isClientCustom && denyCustom)
        p minfo = isNothing (minfo >>= infoNegotiatedGroup) == (null commonGroups && isCustom)
    if shouldFail
        then runTLSInitFailure (clientParam',serverParam')
        else runTLSPipePredicate (clientParam',serverParam') p


prop_handshake_dh :: PropertyM IO ()
prop_handshake_dh = do
    let clientVersions = [TLS12]
        serverVersions = [TLS12]
        ciphers = [ cipher_DHE_RSA_AES128_SHA1 ]
    (clientParam,serverParam) <- pick $ arbitraryPairParamsWithVersionsAndCiphers
                                            (clientVersions, serverVersions)
                                            (ciphers, ciphers)
    let clientParam' = clientParam { clientSupported = (clientSupported clientParam)
                                       { supportedGroups = [] }
                                   }
    let check (dh,shouldFail) = do
         let serverParam' = serverParam { serverDHEParams = Just dh }
         if shouldFail
             then runTLSInitFailure (clientParam',serverParam')
             else runTLSPipeSimple  (clientParam',serverParam')
    mapM_ check [(dhParams512,True)
                ,(dhParams768,True)
                ,(dhParams1024,False)]

prop_handshake_srv_key_usage :: PropertyM IO ()
prop_handshake_srv_key_usage = do
    tls13 <- pick arbitrary
    let versions = if tls13 then [TLS13] else [TLS12,TLS11,TLS10,SSL3]
        ciphers = [ cipher_ECDHE_RSA_AES128CBC_SHA
                  , cipher_TLS13_AES128GCM_SHA256
                  , cipher_DHE_RSA_AES128_SHA1
                  , cipher_AES256_SHA256
                  ]
    (clientParam,serverParam) <- pick $ arbitraryPairParamsWithVersionsAndCiphers
                                            (versions, versions)
                                            (ciphers, ciphers)
    usageFlags <- pick arbitraryKeyUsage
    cred <- pick $ arbitraryRSACredentialWithUsage usageFlags
    let serverParam' = serverParam
            { serverShared = (serverShared serverParam)
                  { sharedCredentials = Credentials [cred]
                  }
            }
        hasDS = KeyUsage_digitalSignature `elem` usageFlags
        hasKE = KeyUsage_keyEncipherment  `elem` usageFlags
        shouldSucceed = hasDS || (hasKE && not tls13)
    if shouldSucceed
        then runTLSPipeSimple  (clientParam,serverParam')
        else runTLSInitFailure (clientParam,serverParam')

prop_handshake_ec :: PropertyM IO ()
prop_handshake_ec = do
    let versions   = [TLS10, TLS11, TLS12, TLS13]
        ciphers    = [ cipher_ECDHE_ECDSA_AES256GCM_SHA384
                     , cipher_ECDHE_ECDSA_AES128CBC_SHA
                     , cipher_TLS13_AES128GCM_SHA256
                     ]
        sigGroups  = [P256]
        ecdhGroups = [X25519, X448] -- always enabled, so no ECDHE failure
        hashSignatures = [ (HashSHA256, SignatureECDSA)
                         ]
    clientVersion <- pick $ elements versions
    (clientParam,serverParam) <- pick $ arbitraryPairParamsWithVersionsAndCiphers
                                            ([clientVersion], versions)
                                            (ciphers, ciphers)
    clientGroups         <- pick $ sublistOf sigGroups
    clientHashSignatures <- pick $ sublistOf hashSignatures
    serverHashSignatures <- pick $ sublistOf hashSignatures
    credentials          <- pick arbitraryCredentialsOfEachCurve
    let clientParam' = clientParam { clientSupported = (clientSupported clientParam)
                                       { supportedGroups = clientGroups ++ ecdhGroups
                                       , supportedHashSignatures = clientHashSignatures
                                       }
                                   }
        serverParam' = serverParam { serverSupported = (serverSupported serverParam)
                                       { supportedGroups = sigGroups ++ ecdhGroups
                                       , supportedHashSignatures = serverHashSignatures
                                       }
                                   , serverShared = (serverShared serverParam)
                                       { sharedCredentials = Credentials credentials }
                                   }
        sigAlgs = map snd (clientHashSignatures `intersect` serverHashSignatures)
        ecdsaDenied = (clientVersion < TLS13 && null clientGroups) ||
                      (clientVersion >= TLS12 && SignatureECDSA `notElem` sigAlgs)
    if ecdsaDenied
        then runTLSInitFailure (clientParam',serverParam')
        else runTLSPipeSimple  (clientParam',serverParam')

prop_handshake_client_auth :: PropertyM IO ()
prop_handshake_client_auth = do
    (clientParam,serverParam) <- pick arbitraryPairParams
    let clientVersions = supportedVersions $ clientSupported clientParam
        serverVersions = supportedVersions $ serverSupported serverParam
        version = maximum (clientVersions `intersect` serverVersions)
    cred <- pick (arbitraryClientCredential version)
    let clientParam' = clientParam { clientHooks = (clientHooks clientParam)
                                       { onCertificateRequest = \_ -> return $ Just cred }
                                   }
        serverParam' = serverParam { serverWantClientCert = True
                                   , serverHooks = (serverHooks serverParam)
                                        { onClientCertificate = validateChain cred }
                                   }
    let shouldFail = version == TLS13 && isCredentialDSA cred
    if shouldFail
        then runTLSInitFailure (clientParam',serverParam')
        else runTLSPipeSimple  (clientParam',serverParam')
  where validateChain cred chain
            | chain == fst cred = return CertificateUsageAccept
            | otherwise         = return (CertificateUsageReject CertificateRejectUnknownCA)

prop_post_handshake_auth :: PropertyM IO ()
prop_post_handshake_auth = do
    (clientParam,serverParam) <- pick arbitraryPairParams13
    cred <- pick (arbitraryClientCredential TLS13)
    let clientParam' = clientParam { clientHooks = (clientHooks clientParam)
                                       { onCertificateRequest = \_ -> return $ Just cred }
                                   }
        serverParam' = serverParam { serverHooks = (serverHooks serverParam)
                                        { onClientCertificate = validateChain cred }
                                   }
    if isCredentialDSA cred
        then runTLSInitFailureGen (clientParam',serverParam') hsServer hsClient
        else runTLSPipe (clientParam',serverParam') tlsServer tlsClient
  where validateChain cred chain
            | chain == fst cred = return CertificateUsageAccept
            | otherwise         = return (CertificateUsageReject CertificateRejectUnknownCA)
        tlsServer ctx queue = do
            hsServer ctx
            d <- recvData ctx
            writeChan queue [d]
            bye ctx
        tlsClient queue ctx = do
            hsClient ctx
            d <- readChan queue
            sendData ctx (L.fromChunks [d])
            byeBye ctx
        hsServer ctx = do
            handshake ctx
            recvDataAssert ctx "request 1"
            _ <- requestCertificate ctx  -- single request
            sendData ctx "response 1"
            recvDataAssert ctx "request 2"
            _ <- requestCertificate ctx
            _ <- requestCertificate ctx  -- two simultaneously
            sendData ctx "response 2"
        hsClient ctx = do
            handshake ctx
            sendData ctx "request 1"
            recvDataAssert ctx "response 1"
            sendData ctx "request 2"
            recvDataAssert ctx "response 2"

prop_handshake_clt_key_usage :: PropertyM IO ()
prop_handshake_clt_key_usage = do
    (clientParam,serverParam) <- pick arbitraryPairParams
    usageFlags <- pick arbitraryKeyUsage
    cred <- pick $ arbitraryRSACredentialWithUsage usageFlags
    let clientParam' = clientParam { clientHooks = (clientHooks clientParam)
                                       { onCertificateRequest = \_ -> return $ Just cred }
                                   }
        serverParam' = serverParam { serverWantClientCert = True
                                   , serverHooks = (serverHooks serverParam)
                                        { onClientCertificate = \_ -> return CertificateUsageAccept }
                                   }
        shouldSucceed = KeyUsage_digitalSignature `elem` usageFlags
    if shouldSucceed
        then runTLSPipeSimple  (clientParam',serverParam')
        else runTLSInitFailure (clientParam',serverParam')

prop_handshake_ems :: PropertyM IO ()
prop_handshake_ems = do
    (cems, sems) <- pick arbitraryEMSMode
    params <- pick arbitraryPairParams
    let params' = setEMSMode (cems, sems) params
        version = getConnectVersion params'
        emsVersion = version >= TLS10 && version <= TLS12
        use = cems /= NoEMS && sems /= NoEMS
        require = cems == RequireEMS || sems == RequireEMS
        p info = infoExtendedMasterSec info == (emsVersion && use)
    if emsVersion && require && not use
        then runTLSInitFailure params'
        else runTLSPipePredicate params' (maybe False p)

prop_handshake_session_resumption_ems :: PropertyM IO ()
prop_handshake_session_resumption_ems = do
    sessionRefs <- run twoSessionRefs
    let sessionManagers = twoSessionManagers sessionRefs

    plainParams <- pick arbitraryPairParams
    ems <- pick (arbitraryEMSMode `suchThat` compatible)
    let params = setEMSMode ems $
            setPairParamsSessionManagers sessionManagers plainParams

    runTLSPipeSimple params

    -- and resume
    sessionParams <- run $ readClientSessionRef sessionRefs
    assert (isJust sessionParams)
    ems2 <- pick (arbitraryEMSMode `suchThat` compatible)
    let params2 = setEMSMode ems2 $
            setPairParamsSessionResuming (fromJust sessionParams) params

    let version    = getConnectVersion params2
        emsVersion = version >= TLS10 && version <= TLS12

    if emsVersion && use ems && not (use ems2)
        then runTLSInitFailure params2
        else do
            runTLSPipeSimple params2
            sessionParams2 <- run $ readClientSessionRef sessionRefs
            let sameSession = sessionParams == sessionParams2
                sameUse     = use ems == use ems2
            when emsVersion $ assert (sameSession == sameUse)
  where
    compatible (NoEMS, RequireEMS) = False
    compatible (RequireEMS, NoEMS) = False
    compatible _                   = True

    use (NoEMS, _) = False
    use (_, NoEMS) = False
    use _          = True

prop_handshake_alpn :: PropertyM IO ()
prop_handshake_alpn = do
    (clientParam,serverParam) <- pick arbitraryPairParams
    let clientParam' = clientParam { clientHooks = (clientHooks clientParam)
                                       { onSuggestALPN = return $ Just ["h2", "http/1.1"] }
                                    }
        serverParam' = serverParam { serverHooks = (serverHooks serverParam)
                                        { onALPNClientSuggest = Just alpn }
                                   }
        params' = (clientParam',serverParam')
    runTLSPipe params' tlsServer tlsClient
  where tlsServer ctx queue = do
            handshake ctx
            proto <- getNegotiatedProtocol ctx
            Just "h2" `assertEq` proto
            d <- recvData ctx
            writeChan queue [d]
            bye ctx
        tlsClient queue ctx = do
            handshake ctx
            proto <- getNegotiatedProtocol ctx
            Just "h2" `assertEq` proto
            d <- readChan queue
            sendData ctx (L.fromChunks [d])
            byeBye ctx
        alpn xs
          | "h2"    `elem` xs = return "h2"
          | otherwise         = return "http/1.1"

prop_handshake_sni :: PropertyM IO ()
prop_handshake_sni = do
    ref <- run $ newIORef Nothing
    (clientParam,serverParam) <- pick arbitraryPairParams
    let clientParam' = clientParam { clientServerIdentification = (serverName, "")
                                   }
        serverParam' = serverParam { serverHooks = (serverHooks serverParam)
                                        { onServerNameIndication = onSNI ref }
                                   }
        params' = (clientParam',serverParam')
    runTLSPipe params' tlsServer tlsClient
    receivedName <- run $ readIORef ref
    Just (Just serverName) `assertEq` receivedName
  where tlsServer ctx queue = do
            handshake ctx
            sni <- getClientSNI ctx
            Just serverName `assertEq` sni
            d <- recvData ctx
            writeChan queue [d]
            bye ctx
        tlsClient queue ctx = do
            handshake ctx
            sni <- getClientSNI ctx
            Just serverName `assertEq` sni
            d <- readChan queue
            sendData ctx (L.fromChunks [d])
            byeBye ctx
        onSNI ref name = assertEmptyRef ref >> writeIORef ref (Just name) >>
                         return (Credentials [])
        serverName = "haskell.org"

prop_handshake_renegotiation :: PropertyM IO ()
prop_handshake_renegotiation = do
    renegDisabled <- pick arbitrary
    (cparams, sparams) <- pick arbitraryPairParams
    let sparams' = sparams {
            serverSupported = (serverSupported sparams) {
                 supportedClientInitiatedRenegotiation = not renegDisabled
               }
          }
    if renegDisabled || isVersionEnabled TLS13 (cparams, sparams')
        then runTLSInitFailureGen (cparams, sparams') hsServer hsClient
        else runTLSPipe (cparams, sparams') tlsServer tlsClient
  where tlsServer ctx queue = do
            hsServer ctx
            d <- recvData ctx
            writeChan queue [d]
            bye ctx
        tlsClient queue ctx = do
            hsClient ctx
            d <- readChan queue
            sendData ctx (L.fromChunks [d])
            byeBye ctx
        hsServer     = handshake
        hsClient ctx = handshake ctx >> handshake ctx

prop_handshake_session_resumption :: PropertyM IO ()
prop_handshake_session_resumption = do
    sessionRefs <- run twoSessionRefs
    let sessionManagers = twoSessionManagers sessionRefs

    plainParams <- pick arbitraryPairParams
    let params = setPairParamsSessionManagers sessionManagers plainParams

    runTLSPipeSimple params

    -- and resume
    sessionParams <- run $ readClientSessionRef sessionRefs
    assert (isJust sessionParams)
    let params2 = setPairParamsSessionResuming (fromJust sessionParams) params

    runTLSPipeSimple params2

prop_thread_safety :: PropertyM IO ()
prop_thread_safety = do
    params  <- pick arbitraryPairParams
    runTLSPipe params tlsServer tlsClient
  where tlsServer ctx queue = do
            handshake ctx
            runReaderWriters ctx "client-value" "server-value"
            d <- recvData ctx
            writeChan queue [d]
            bye ctx
        tlsClient queue ctx = do
            handshake ctx
            runReaderWriters ctx "server-value" "client-value"
            d <- readChan queue
            sendData ctx (L.fromChunks [d])
            byeBye ctx
        runReaderWriters ctx r w =
            -- run concurrently 10 readers and 10 writers on the same context
            let workers = concat $ replicate 10 [recvDataAssert ctx r, sendData ctx w]
             in runConcurrently $ traverse_ Concurrently workers

assertEq :: (Show a, Monad m, Eq a) => a -> a -> m ()
assertEq expected got = unless (expected == got) $ error ("got " ++ show got ++ " but was expecting " ++ show expected)

assertIsLeft :: (Show b, Monad m) => Either a b -> m ()
assertIsLeft (Left  _) = return ()
assertIsLeft (Right b) = error ("got " ++ show b ++ " but was expecting a failure")

assertEmptyRef :: Show a => IORef (Maybe a) -> IO ()
assertEmptyRef ref = readIORef ref >>= maybe (return ()) (\a ->
    error ("got " ++ show a ++ " but was expecting empty reference"))

recvDataAssert :: Context -> C8.ByteString -> IO ()
recvDataAssert ctx expected = do
    got <- recvData ctx
    assertEq expected got

main :: IO ()
main = defaultMain $ testGroup "tls"
    [ tests_marshalling
    , tests_ciphers
    , tests_handshake
    , tests_thread_safety
    ]
  where -- lowlevel tests to check the packet marshalling.
        tests_marshalling = testGroup "Marshalling"
            [ testProperty "Header" prop_header_marshalling_id
            , testProperty "Handshake" prop_handshake_marshalling_id
            , testProperty "Handshake13" prop_handshake13_marshalling_id
            ]
        tests_ciphers = testGroup "Ciphers"
            [ testProperty "Bulk" propertyBulkFunctional ]

        -- high level tests between a client and server with fake ciphers.
        tests_handshake = testGroup "Handshakes"
            [ testProperty "Setup" (monadicIO prop_pipe_work)
            , testProperty "Initiation" (monadicIO prop_handshake_initiate)
            , testProperty "Initiation 1.3" (monadicIO prop_handshake13_initiate)
            , testProperty "Key update 1.3" (monadicIO prop_handshake_keyupdate)
            , testProperty "Downgrade protection" (monadicIO prop_handshake13_downgrade)
            , testProperty "Hash and signatures" (monadicIO prop_handshake_hashsignatures)
            , testProperty "Cipher suites" (monadicIO prop_handshake_ciphersuites)
            , testProperty "Groups" (monadicIO prop_handshake_groups)
            , testProperty "Elliptic curves" (monadicIO prop_handshake_ec)
            , testProperty "Certificate fallback (ciphers)" (monadicIO prop_handshake_cert_fallback)
            , testProperty "Certificate fallback (hash and signatures)" (monadicIO prop_handshake_cert_fallback_hs)
            , testProperty "Server key usage" (monadicIO prop_handshake_srv_key_usage)
            , testProperty "Client authentication" (monadicIO prop_handshake_client_auth)
            , testProperty "Client key usage" (monadicIO prop_handshake_clt_key_usage)
            , testProperty "Extended Master Secret" (monadicIO prop_handshake_ems)
            , testProperty "Extended Master Secret (resumption)" (monadicIO prop_handshake_session_resumption_ems)
            , testProperty "ALPN" (monadicIO prop_handshake_alpn)
            , testProperty "SNI" (monadicIO prop_handshake_sni)
            , testProperty "Renegotiation" (monadicIO prop_handshake_renegotiation)
            , testProperty "Resumption" (monadicIO prop_handshake_session_resumption)
            , testProperty "Custom DH" (monadicIO prop_handshake_dh)
            , testProperty "TLS 1.3 Full" (monadicIO prop_handshake13_full)
            , testProperty "TLS 1.3 HRR"  (monadicIO prop_handshake13_hrr)
            , testProperty "TLS 1.3 PSK"  (monadicIO prop_handshake13_psk)
            , testProperty "TLS 1.3 PSK -> HRR" (monadicIO prop_handshake13_psk_fallback)
            , testProperty "TLS 1.3 RTT0" (monadicIO prop_handshake13_rtt0)
            , testProperty "TLS 1.3 RTT0 -> PSK" (monadicIO prop_handshake13_rtt0_fallback)
            , testProperty "TLS 1.3 RTT0 length" (monadicIO prop_handshake13_rtt0_length)
            , testProperty "TLS 1.3 EE groups" (monadicIO prop_handshake13_ee_groups)
            , testProperty "TLS 1.3 Post-handshake auth" (monadicIO prop_post_handshake_auth)
            ]

        -- test concurrent reads and writes
        tests_thread_safety = localOption (QuickCheckTests 10) $
            testProperty "Thread safety" (monadicIO prop_thread_safety)
