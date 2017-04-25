module Connection
    ( newPairContext
    , arbitraryHashSignatures
    , arbitraryPairParams
    , arbitraryPairParamsWithVersionsAndCiphers
    , arbitraryClientCredential
    , oneSessionManager
    , setPairParamsSessionManager
    , setPairParamsSessionResuming
    , establishDataPipe
    , initiateDataPipe
    ) where

import Test.Tasty.QuickCheck
import Certificate
import PubKey
import PipeChan
import Network.TLS as TLS
import Network.TLS.Extra
import Data.X509
import Data.Default.Class
import Data.IORef
import Control.Applicative
import Control.Concurrent.Chan
import Control.Concurrent
import qualified Control.Exception as E
import Data.List (isInfixOf)

import qualified Data.ByteString as B

debug :: Bool
debug = False

knownCiphers :: [Cipher]
knownCiphers = filter nonECDSA (ciphersuite_all ++ ciphersuite_weak)
  where
    ciphersuite_weak = [
        cipher_DHE_DSS_RC4_SHA1
      , cipher_RC4_128_MD5
      , cipher_null_MD5
      , cipher_null_SHA1
      ]
    -- arbitraryCredentialsOfEachType cannot generate ECDSA
    nonECDSA c = not ("ECDSA" `isInfixOf` cipherName c)

knownVersions :: [Version]
knownVersions = [SSL3,TLS10,TLS11,TLS12]

knownHashSignatures :: [HashAndSignatureAlgorithm]
knownHashSignatures = filter nonECDSA availableHashSignatures
  where
    availableHashSignatures = [(TLS.HashTLS13,  SignatureRSApssSHA256)
                              ,(TLS.HashSHA512, SignatureRSA)
                              ,(TLS.HashSHA512, SignatureECDSA)
                              ,(TLS.HashSHA384, SignatureRSA)
                              ,(TLS.HashSHA384, SignatureECDSA)
                              ,(TLS.HashSHA256, SignatureRSA)
                              ,(TLS.HashSHA256, SignatureECDSA)
                              ,(TLS.HashSHA1,   SignatureRSA)
                              ,(TLS.HashSHA1,   SignatureDSS)
                              ]
    -- arbitraryCredentialsOfEachType cannot generate ECDSA
    nonECDSA (_,s) = s /= SignatureECDSA

arbitraryHashSignatures :: Gen [HashAndSignatureAlgorithm]
arbitraryHashSignatures = sublistOf knownHashSignatures

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
        arbitraryCiphers  = listOf1 $ elements knownCiphers

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

arbitraryGroupPair :: Gen ([Group], [Group])
arbitraryGroupPair = do
    serverGroups <- arbitraryGroups
    clientGroups <- oneof [arbitraryGroups] `suchThat`
                         (\gs -> or [x `elem` serverGroups | x <- gs])
    return (clientGroups, serverGroups)
  where
    availableGroups = [P256,P384,P521,X25519,X448]
    arbitraryGroups = listOf1 $ elements availableGroups

arbitraryHashSignaturePair :: Gen ([HashAndSignatureAlgorithm], [HashAndSignatureAlgorithm])
arbitraryHashSignaturePair = do
    serverHashSignatures <- shuffle knownHashSignatures
    clientHashSignatures <- shuffle knownHashSignatures
    return (clientHashSignatures, serverHashSignatures)

arbitraryPairParamsWithVersionsAndCiphers :: ([Version], [Version])
                                          -> ([Cipher], [Cipher])
                                          -> Gen (ClientParams, ServerParams)
arbitraryPairParamsWithVersionsAndCiphers (clientVersions, serverVersions) (clientCiphers, serverCiphers) = do
    secNeg             <- arbitrary
    dhparams           <- elements [dhParams,ffdhe2048,ffdhe3072]

    creds              <- arbitraryCredentialsOfEachType
    (clientGroups, serverGroups) <- arbitraryGroupPair
    (clientHashSignatures, serverHashSignatures) <- arbitraryHashSignaturePair
    let serverState = def
            { serverSupported = def { supportedCiphers  = serverCiphers
                                    , supportedVersions = serverVersions
                                    , supportedSecureRenegotiation = secNeg
                                    , supportedGroups   = serverGroups
                                    , supportedHashSignatures = serverHashSignatures
                                    }
            , serverDHEParams = Just dhparams
            , serverShared = def { sharedCredentials = Credentials creds }
            }
    let clientState = (defaultParamsClient "" B.empty)
            { clientSupported = def { supportedCiphers  = clientCiphers
                                    , supportedVersions = clientVersions
                                    , supportedSecureRenegotiation = secNeg
                                    , supportedGroups   = clientGroups
                                    , supportedHashSignatures = clientHashSignatures
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
