module Connection
    ( newPairContext
    , arbitraryPairParams
    , arbitraryPairParamsWithVersionsAndCiphers
    , arbitraryClientCredential
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
import Network.TLS.Extra.FFDHE
import Data.X509
import Data.Default.Class
import Control.Applicative
import Control.Concurrent.Chan
import Control.Concurrent
import qualified Control.Exception as E

import qualified Data.ByteString as B

debug :: Bool
debug = False

blockCipher :: Cipher
blockCipher = Cipher
    { cipherID   = 0xff12
    , cipherName = "rsa-id-const"
    , cipherBulk = Bulk
        { bulkName      = "id"
        , bulkKeySize   = 16
        , bulkIVSize    = 16
        , bulkExplicitIV= 0
        , bulkAuthTagLen= 0
        , bulkBlockSize = 16
        , bulkF         = BulkBlockF $ \_ _ _ -> (\m -> (m, B.empty))
        }
    , cipherHash        = MD5
    , cipherPRFHash     = Nothing
    , cipherKeyExchange = CipherKeyExchange_RSA
    , cipherMinVer      = Nothing
    }

blockCipherDHE_RSA :: Cipher
blockCipherDHE_RSA = blockCipher
    { cipherID   = 0xff14
    , cipherName = "dhe-rsa-id-const"
    , cipherKeyExchange = CipherKeyExchange_DHE_RSA
    }

blockCipherDHE_DSS :: Cipher
blockCipherDHE_DSS = blockCipher
    { cipherID   = 0xff15
    , cipherName = "dhe-dss-id-const"
    , cipherKeyExchange = CipherKeyExchange_DHE_DSS
    }

blockCipherECDHE_RSA :: Cipher
blockCipherECDHE_RSA = blockCipher
    { cipherID   = 0xff16
    , cipherName = "ecdhe-rsa-id-const"
    , cipherKeyExchange  = CipherKeyExchange_ECDHE_RSA
    }

blockCipherECDHE_RSA_SHA384 :: Cipher
blockCipherECDHE_RSA_SHA384 = blockCipher
    { cipherID   = 0xff17
    , cipherName = "ecdhe-rsa-id-const-sha384"
    , cipherKeyExchange  = CipherKeyExchange_ECDHE_RSA
    , cipherHash        = SHA384
    , cipherPRFHash     = Just SHA384
    , cipherMinVer      = Just TLS12
    }

streamCipher :: Cipher
streamCipher = blockCipher
    { cipherID   = 0xff13
    , cipherBulk = Bulk
        { bulkName      = "stream"
        , bulkKeySize   = 16
        , bulkIVSize    = 0
        , bulkExplicitIV= 0
        , bulkAuthTagLen= 0
        , bulkBlockSize = 0
        , bulkF         = BulkStreamF passThrough
        }
    }
  where
    passThrough _ _ = BulkStream go where go inp = (inp, BulkStream go)

knownCiphers :: [Cipher]
knownCiphers = [ blockCipher
               , blockCipherDHE_RSA
               , blockCipherDHE_DSS
               , blockCipherECDHE_RSA
               , blockCipherECDHE_RSA_SHA384
               , streamCipher
               ]

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

arbitraryPairParamsWithVersionsAndCiphers :: ([Version], [Version])
                                          -> ([Cipher], [Cipher])
                                          -> Gen (ClientParams, ServerParams)
arbitraryPairParamsWithVersionsAndCiphers (clientVersions, serverVersions) (clientCiphers, serverCiphers) = do
    secNeg             <- arbitrary
    dhparams           <- elements [dhParams,ffdhe2048,ffdhe3072]

    creds              <- arbitraryCredentialsOfEachType
    let serverState = def
            { serverSupported = def { supportedCiphers  = serverCiphers
                                    , supportedVersions = serverVersions
                                    , supportedSecureRenegotiation = secNeg
                                    }
            , serverDHEParams = Just dhparams
            , serverShared = def { sharedCredentials = Credentials creds }
            }
    let clientState = (defaultParamsClient "" B.empty)
            { clientSupported = def { supportedCiphers  = clientCiphers
                                    , supportedVersions = clientVersions
                                    , supportedSecureRenegotiation = secNeg
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

setPairParamsSessionManager :: SessionManager -> (ClientParams, ServerParams) -> (ClientParams, ServerParams)
setPairParamsSessionManager manager (clientState, serverState) = (nc,ns)
  where nc = clientState { clientShared = updateSessionManager $ clientShared clientState }
        ns = serverState { serverShared = updateSessionManager $ serverShared serverState }
        updateSessionManager shared = shared { sharedSessionManager = manager }

setPairParamsSessionResuming :: (SessionID, SessionData) -> (ClientParams, t) -> (ClientParams, t)
setPairParamsSessionResuming sessionStuff (clientState, serverState) =
    ( clientState { clientWantSessionResume = Just sessionStuff }
    , serverState)

newPairContext :: (TLSParams params, TLSParams params1) => PipeChan -> (params1, params) -> IO (Context, Context)
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

establishDataPipe :: (ClientParams, ServerParams) -> (Context -> Chan a1 -> IO ()) -> (Chan a -> Context -> IO ()) -> IO (Chan a, Chan a1)
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

initiateDataPipe :: (TLSParams params1, TLSParams params) => (params1, params) -> (Context -> IO a1) -> (Context -> IO a) -> IO (Either E.SomeException a, Either E.SomeException a1)
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
