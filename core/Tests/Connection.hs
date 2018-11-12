-- Disable this warning so we can still test deprecated functionality.
{-# OPTIONS_GHC -fno-warn-warnings-deprecations #-}
module Connection
    ( newPairContext
    , arbitraryCiphers
    , arbitraryVersions
    , arbitraryHashSignatures
    , arbitraryGroups
    , arbitraryKeyUsage
    , arbitraryPairParams
    , arbitraryPairParams13
    , arbitraryPairParamsWithVersionsAndCiphers
    , arbitraryClientCredential
    , arbitraryRSACredentialWithUsage
    , isCustomDHParams
    , leafPublicKey
    , readClientSessionRef
    , twoSessionRefs
    , twoSessionManagers
    , setPairParamsSessionManagers
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
import Control.Concurrent.Async
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

knownCiphers13 :: [Cipher]
knownCiphers13 = [
    cipher_TLS13_AES128GCM_SHA256
  , cipher_TLS13_AES256GCM_SHA384
  ]

arbitraryCiphers :: Gen [Cipher]
arbitraryCiphers = listOf1 $ elements knownCiphers

knownVersions :: [Version]
knownVersions = [SSL3,TLS10,TLS11,TLS12,TLS13]

arbitraryVersions :: Gen [Version]
arbitraryVersions = sublistOf knownVersions

knownHashSignatures :: [HashAndSignatureAlgorithm]
knownHashSignatures = filter nonECDSA availableHashSignatures
  where
    availableHashSignatures = [(TLS.HashIntrinsic, SignatureRSApssRSAeSHA512)
                              ,(TLS.HashIntrinsic, SignatureRSApssRSAeSHA384)
                              ,(TLS.HashIntrinsic, SignatureRSApssRSAeSHA256)
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

-- for performance reason P521, FFDHE6144, FFDHE8192 are not tested
knownGroups, knownECGroups, knownFFGroups :: [Group]
knownECGroups = [P256,P384,X25519,X448]
knownFFGroups = [FFDHE2048,FFDHE3072,FFDHE4096]
knownGroups   = knownECGroups ++ knownFFGroups

arbitraryGroups :: Gen [Group]
arbitraryGroups = listOf1 $ elements knownGroups

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

isCustomDHParams :: DHParams -> Bool
isCustomDHParams params = params == dhParams512

leafPublicKey :: CertificateChain -> Maybe PubKey
leafPublicKey (CertificateChain [])       = Nothing
leafPublicKey (CertificateChain (leaf:_)) = Just (certPubKey $ signedObject $ getSigned leaf)

arbitraryCipherPair :: Version -> Gen ([Cipher], [Cipher])
arbitraryCipherPair connectVersion = do
    serverCiphers      <- arbitraryCiphers `suchThat`
                                (\cs -> or [cipherAllowedForVersion connectVersion x | x <- cs])
    clientCiphers      <- arbitraryCiphers `suchThat`
                                (\cs -> or [x `elem` serverCiphers &&
                                            cipherAllowedForVersion connectVersion x | x <- cs])
    return (clientCiphers, serverCiphers)

arbitraryPairParams :: Gen (ClientParams, ServerParams)
arbitraryPairParams = do
    connectVersion <- elements knownVersions
    (clientCiphers, serverCiphers) <- arbitraryCipherPair connectVersion
    -- The shared ciphers may add constraints on the compatible protocol versions
    let allowedVersions = [ v | v <- knownVersions,
                                or [ x `elem` serverCiphers &&
                                     cipherAllowedForVersion v x | x <- clientCiphers ]]
    serAllowedVersions <- (:[]) `fmap` elements allowedVersions
    arbitraryPairParamsWithVersionsAndCiphers (allowedVersions, serAllowedVersions) (clientCiphers, serverCiphers)

-- pair of groups so that at least one EC and one FF group are in common
arbitraryGroupPair :: Gen ([Group], [Group])
arbitraryGroupPair = do
    (serverECGroups, clientECGroups) <- arbitraryGroupPairFrom knownECGroups
    (serverFFGroups, clientFFGroups) <- arbitraryGroupPairFrom knownFFGroups
    serverGroups <- shuffle (serverECGroups ++ serverFFGroups)
    clientGroups <- shuffle (clientECGroups ++ clientFFGroups)
    return (clientGroups, serverGroups)
  where
    arbitraryGroupPairFrom list = do
        s <- arbitraryGroupsFrom list
        c <- arbitraryGroupsFrom list `suchThat` any (`elem` s)
        return (c, s)
    arbitraryGroupsFrom list = listOf1 $ elements list

arbitraryPairParams13 :: Gen (ClientParams, ServerParams)
arbitraryPairParams13 = do
    let connectVersion = TLS13
        allowedVersions = [connectVersion]
        serAllowedVersions = [connectVersion]
    (clientCiphers', serverCiphers') <- arbitraryCipherPair connectVersion
    cipher <- elements knownCiphers13
    let clientCiphers = clientCiphers' ++ [cipher]
        serverCiphers = serverCiphers' ++ [cipher]
    arbitraryPairParamsWithVersionsAndCiphers (allowedVersions, serAllowedVersions) (clientCiphers, serverCiphers)

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
    dhparams           <- elements [dhParams512,ffdhe2048,ffdhe3072]

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

arbitraryRSACredentialWithUsage :: [ExtKeyUsageFlag] -> Gen (CertificateChain, PrivKey)
arbitraryRSACredentialWithUsage usageFlags = do
    let (pubKey, privKey) = getGlobalRSAPair
    cert <- arbitraryX509WithKeyAndUsage usageFlags (PubKeyRSA pubKey, ())
    return (CertificateChain [cert], PrivKeyRSA privKey)

readClientSessionRef :: (IORef mclient, IORef mserver) -> IO mclient
readClientSessionRef refs = readIORef (fst refs)

twoSessionRefs :: IO (IORef (Maybe client), IORef (Maybe server))
twoSessionRefs = (,) <$> newIORef Nothing <*> newIORef Nothing

-- | simple session manager to store one session id and session data for a single thread.
-- a Real concurrent session manager would use an MVar and have multiples items.
oneSessionManager :: IORef (Maybe (SessionID, SessionData)) -> SessionManager
oneSessionManager ref = SessionManager
    { sessionResume         = \myId     -> (>>= maybeResume myId) <$> readIORef ref
    , sessionResumeOnlyOnce = \myId     -> (>>= maybeResume myId) <$> readIORef ref
    , sessionEstablish      = \myId dat -> writeIORef ref $ Just (myId, dat)
    , sessionInvalidate     = \_        -> return ()
    }
  where
    maybeResume myId (sid, sdata)
        | sid == myId = Just sdata
        | otherwise   = Nothing

twoSessionManagers :: (IORef (Maybe (SessionID, SessionData)), IORef (Maybe (SessionID, SessionData))) -> (SessionManager, SessionManager)
twoSessionManagers (cRef, sRef) = (oneSessionManager cRef, oneSessionManager sRef)

setPairParamsSessionManagers :: (SessionManager, SessionManager) -> (ClientParams, ServerParams) -> (ClientParams, ServerParams)
setPairParamsSessionManagers (clientManager, serverManager) (clientState, serverState) = (nc,ns)
  where nc = clientState { clientShared = updateSessionManager clientManager $ clientShared clientState }
        ns = serverState { serverShared = updateSessionManager serverManager $ serverShared serverState }
        updateSessionManager manager shared = shared { sharedSessionManager = manager }

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

establishDataPipe :: (ClientParams, ServerParams) -> (Context -> Chan result -> IO ()) -> (Chan start -> Context -> IO ()) -> IO (start -> IO (), IO result)
establishDataPipe params tlsServer tlsClient = do
    -- initial setup
    pipe        <- newPipe
    _           <- runPipe pipe
    startQueue  <- newChan
    resultQueue <- newChan

    (cCtx, sCtx) <- newPairContext pipe params

    sAsync <- async $ E.catch (tlsServer sCtx resultQueue)
                              (printAndRaise "server" (serverSupported $ snd params))
    cAsync <- async $ E.catch (tlsClient startQueue cCtx)
                              (printAndRaise "client" (clientSupported $ fst params))

    let readResult = waitBoth cAsync sAsync >> readChan resultQueue
    return (writeChan startQueue, readResult)
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
    _           <- runPipe pipe

    (cCtx, sCtx) <- newPairContext pipe params

    withAsync (tlsServer sCtx) $ \sAsync ->
        withAsync (tlsClient cCtx) $ \cAsync -> do
            sRes <- waitCatch sAsync
            cRes <- waitCatch cAsync
            return (cRes, sRes)
