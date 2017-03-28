module Connection
    ( newPairContext
    , arbitraryPairParams
    , arbitraryPairParamsWithVersionsAndCiphers
    , arbitraryClientCredential
    , oneSessionManager
    , setPairParamsSessionManager
    , setPairParamsSessionResuming
    , establishDataPipe
    , initiateDataPipe
    , blockCipher
    , blockCipherDHE_RSA
    , blockCipherDHE_DSS
    , blockCipherECDHE_RSA
    , blockCipherECDHE_RSA_SHA384
    , streamCipher
    ) where

import Test.Tasty.QuickCheck
import Certificate
import PubKey
import PipeChan
import Network.TLS
import Network.TLS.Extra
import Data.X509
import Data.Default.Class
import Data.IORef
import Control.Applicative
import Control.Concurrent.Chan
import Control.Concurrent
import qualified Control.Exception as E
import Data.List (isPrefixOf, intersect)

import qualified Data.ByteString as B

debug :: Bool
debug = False

blockCipher :: Cipher
blockCipher = cipher_AES128_SHA1

blockCipherDHE_RSA :: Cipher
blockCipherDHE_RSA = cipher_DHE_RSA_AES128_SHA1

blockCipherDHE_DSS :: Cipher
blockCipherDHE_DSS = cipher_DHE_DSS_AES128_SHA1

blockCipherECDHE_RSA :: Cipher
blockCipherECDHE_RSA = cipher_ECDHE_RSA_AES128CBC_SHA

-- TLS 1.2 only
blockCipherECDHE_RSA_SHA384 :: Cipher
blockCipherECDHE_RSA_SHA384 = cipher_ECDHE_RSA_AES256GCM_SHA384

streamCipher :: Cipher
streamCipher = cipher_RC4_128_SHA1

knownCiphers :: [Cipher]
knownCiphers = [ blockCipher
               , blockCipherDHE_RSA
               , blockCipherDHE_DSS
               , blockCipherECDHE_RSA
               , blockCipherECDHE_RSA_SHA384
               , streamCipher
               ]

isNonECCipher :: Cipher -> Bool
isNonECCipher cipher = not ("EC" `isPrefixOf` cipherName cipher)

knownVersions :: [Version]
knownVersions = [SSL3,TLS10,TLS11,TLS12]

arbitraryCredentialsOfEachType :: Gen [(CertificateChain, PrivKey)]
arbitraryCredentialsOfEachType = do
    let (pubKey, privKey) = getGlobalRSAPair
    (dsaPub, dsaPriv) <- arbitraryDSAPair
    mapM (\(pub, priv) -> do
              cert <- arbitraryX509WithKey (pub, priv)
              return (CertificateChain [cert], priv)
         ) [ (PubKeyRSA pubKey, PrivKeyRSA privKey)
           , (PubKeyDSA dsaPub, PrivKeyDSA dsaPriv)
           ]

arbitraryCipherPair :: Version -> Gen ([Cipher], [Cipher])
arbitraryCipherPair connectVersion = do
    serverCiphers      <- arbitraryCiphers `suchThat`
                                (\cs -> or [maybe True (<= connectVersion) (cipherMinVer x) | x <- cs])
    clientCiphers      <- oneof [arbitraryCiphers] `suchThat`
                                (\cs -> or [x `elem` serverCiphers &&
                                            maybe True (<= connectVersion) (cipherMinVer x) | x <- cs])
    return (clientCiphers, serverCiphers)
  where
        arbitraryCiphers  = resize (length knownCiphers + 1) $ listOf1 (elements knownCiphers)

arbitraryPairParams :: Gen (ClientParams, ServerParams)
arbitraryPairParams = do
    connectVersion <- elements knownVersions
    (clientCiphers, serverCiphers) <- arbitraryCipherPair connectVersion
    -- The shared ciphers may set a floor on the compatible protocol versions
    let allowedVersions = [ v | v <- knownVersions,
                                or [ x `elem` serverCiphers &&
                                     maybe True (<= v) (cipherMinVer x) | x <- clientCiphers ]]
    serAllowedVersions <- (:[]) `fmap` elements allowedVersions
    arbitraryPairParamsWithVersionsAndCiphers (allowedVersions, serAllowedVersions) (clientCiphers, serverCiphers)

arbitraryGroupPair :: ([Cipher], [Cipher]) -> Gen ([Group], [Group])
arbitraryGroupPair (clientCiphers, serverCiphers) = do
    groupServer <- sublistOf availableGroups
    groupClient <- sublistOf availableGroups
    common <- elements availableGroups
    if hasNonEC then return (groupClient, groupServer)
                else return (groupClient ++ [common], groupServer ++ [common])
  where
    commonCiphers = serverCiphers `intersect` clientCiphers
    hasNonEC = any isNonECCipher commonCiphers
    availableGroups = [P256,P384,P521,X25519,X448]

arbitraryPairParamsWithVersionsAndCiphers :: ([Version], [Version])
                                          -> ([Cipher], [Cipher])
                                          -> Gen (ClientParams, ServerParams)
arbitraryPairParamsWithVersionsAndCiphers (clientVersions, serverVersions) (clientCiphers, serverCiphers) = do
    secNeg             <- arbitrary
    dhparams           <- elements [dhParams,ffdhe2048,ffdhe3072]

    creds              <- arbitraryCredentialsOfEachType
    (groupClient, groupServer) <- arbitraryGroupPair (clientCiphers, serverCiphers)
    let serverState = def
            { serverSupported = def { supportedCiphers  = serverCiphers
                                    , supportedVersions = serverVersions
                                    , supportedSecureRenegotiation = secNeg
                                    , supportedGroups   = groupServer
                                    }
            , serverDHEParams = Just dhparams
            , serverShared = def { sharedCredentials = Credentials creds }
            }
    let clientState = (defaultParamsClient "" B.empty)
            { clientSupported = def { supportedCiphers  = clientCiphers
                                    , supportedVersions = clientVersions
                                    , supportedSecureRenegotiation = secNeg
                                    , supportedGroups   = groupClient
                                    }
            , clientShared = def { sharedValidationCache = ValidationCache
                                        { cacheAdd = \_ _ _ -> return ()
                                        , cacheQuery = \_ _ _ -> return ValidationCachePass
                                        }
                                }
            }
    return (clientState, serverState)

arbitraryClientCredential :: Gen Credential
arbitraryClientCredential = arbitraryCredentialsOfEachType >>= elements

-- | simple session manager to store one session id and session data for a single thread.
-- a Real concurrent session manager would use an MVar and have multiples items.
oneSessionManager :: IORef (Maybe (SessionID, SessionData)) -> SessionManager
oneSessionManager ref = SessionManager
    { sessionResume     = \myId     -> (>>= maybeResume myId) <$> readIORef ref
    , sessionEstablish  = \myId dat -> writeIORef ref $ Just (myId, dat)
    , sessionInvalidate = \_        -> return ()
    }
  where
    maybeResume myId (sid, sdata)
        | sid == myId = Just sdata
        | otherwise   = Nothing

setPairParamsSessionManager :: SessionManager -> (ClientParams, ServerParams) -> (ClientParams, ServerParams)
setPairParamsSessionManager manager (clientState, serverState) = (nc,ns)
  where nc = clientState { clientShared = updateSessionManager $ clientShared clientState }
        ns = serverState { serverShared = updateSessionManager $ serverShared serverState }
        updateSessionManager shared = shared { sharedSessionManager = manager }

setPairParamsSessionResuming :: (SessionID, SessionData) -> (ClientParams, ServerParams) -> (ClientParams, ServerParams)
setPairParamsSessionResuming sessionStuff (clientState, serverState) =
    ( clientState { clientWantSessionResume = Just sessionStuff }
    , serverState)

newPairContext :: PipeChan -> (ClientParams, ServerParams) -> IO (Context, Context)
newPairContext pipe (cParams, sParams) = do
    let noFlush = return ()
    let noClose = return ()

    let cBackend = Backend noFlush noClose (writePipeA pipe) (readPipeA pipe)
    let sBackend = Backend noFlush noClose (writePipeB pipe) (readPipeB pipe)
    cCtx' <- contextNew cBackend cParams
    sCtx' <- contextNew sBackend sParams

    contextHookSetLogging cCtx' (logging "client: ")
    contextHookSetLogging sCtx' (logging "server: ")

    return (cCtx', sCtx')
  where
        logging pre =
            if debug
                then def { loggingPacketSent = putStrLn . ((pre ++ ">> ") ++)
                                    , loggingPacketRecv = putStrLn . ((pre ++ "<< ") ++) }
                else def

establishDataPipe :: (ClientParams, ServerParams) -> (Context -> Chan result -> IO ()) -> (Chan start -> Context -> IO ()) -> IO (Chan start, Chan result)
establishDataPipe params tlsServer tlsClient = do
    -- initial setup
    pipe        <- newPipe
    _           <- (runPipe pipe)
    startQueue  <- newChan
    resultQueue <- newChan

    (cCtx, sCtx) <- newPairContext pipe params

    _ <- forkIO $ E.catch (tlsServer sCtx resultQueue)
                          (printAndRaise "server" (serverSupported $ snd params))
    _ <- forkIO $ E.catch (tlsClient startQueue cCtx)
                          (printAndRaise "client" (clientSupported $ fst params))

    return (startQueue, resultQueue)
  where
        printAndRaise :: String -> Supported -> E.SomeException -> IO ()
        printAndRaise s supported e = do
            putStrLn $ s ++ " exception: " ++ show e ++
                           ", supported: " ++ show supported
            E.throw e

initiateDataPipe :: (ClientParams, ServerParams) -> (Context -> IO a1) -> (Context -> IO a) -> IO (Either E.SomeException a, Either E.SomeException a1)
initiateDataPipe params tlsServer tlsClient = do
    -- initial setup
    pipe        <- newPipe
    _           <- (runPipe pipe)
    cQueue      <- newChan
    sQueue      <- newChan

    (cCtx, sCtx) <- newPairContext pipe params

    _ <- forkIO $ E.catch (tlsServer sCtx >>= writeSuccess sQueue)
                          (writeException sQueue)
    _ <- forkIO $ E.catch (tlsClient cCtx >>= writeSuccess cQueue)
                          (writeException cQueue)

    sRes <- readChan sQueue
    cRes <- readChan cQueue
    return (cRes, sRes)
  where
        writeException :: Chan (Either E.SomeException a) -> E.SomeException -> IO ()
        writeException queue e = writeChan queue (Left e)

        writeSuccess :: Chan (Either E.SomeException a) -> a -> IO ()
        writeSuccess queue res = writeChan queue (Right res)
