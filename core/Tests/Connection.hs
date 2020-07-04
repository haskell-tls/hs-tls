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
    , arbitraryCredentialsOfEachCurve
    , arbitraryRSACredentialWithUsage
    , dhParamsGroup
    , getConnectVersion
    , isVersionEnabled
    , isCustomDHParams
    , isLeafRSA
    , isCredentialDSA
    , arbitraryEMSMode
    , setEMSMode
    , readClientSessionRef
    , twoSessionRefs
    , twoSessionManagers
    , setPairParamsSessionManagers
    , setPairParamsSessionResuming
    , withDataPipe
    , initiateDataPipe
    , byeBye
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
import Control.Monad (unless, when)
import Data.List (intersect, isInfixOf)

import qualified Data.ByteString as B

debug :: Bool
debug = False

knownCiphers :: [Cipher]
knownCiphers = ciphersuite_all ++ ciphersuite_weak
  where
    ciphersuite_weak = [
        cipher_DHE_DSS_RC4_SHA1
      , cipher_RC4_128_MD5
      , cipher_null_MD5
      , cipher_null_SHA1
      ]

arbitraryCiphers :: Gen [Cipher]
arbitraryCiphers = listOf1 $ elements knownCiphers

knownVersions :: [Version]
knownVersions = [TLS13,TLS12,TLS11,TLS10,SSL3]

arbitraryVersions :: Gen [Version]
arbitraryVersions = sublistOf knownVersions

-- for performance reason ecdsa_secp521r1_sha512 is not tested
knownHashSignatures :: [HashAndSignatureAlgorithm]
knownHashSignatures =         [(TLS.HashIntrinsic, SignatureRSApssRSAeSHA512)
                              ,(TLS.HashIntrinsic, SignatureRSApssRSAeSHA384)
                              ,(TLS.HashIntrinsic, SignatureRSApssRSAeSHA256)
                              ,(TLS.HashIntrinsic, SignatureEd25519)
                              ,(TLS.HashIntrinsic, SignatureEd448)
                              ,(TLS.HashSHA512, SignatureRSA)
                              ,(TLS.HashSHA384, SignatureRSA)
                              ,(TLS.HashSHA384, SignatureECDSA)
                              ,(TLS.HashSHA256, SignatureRSA)
                              ,(TLS.HashSHA256, SignatureECDSA)
                              ,(TLS.HashSHA1,   SignatureRSA)
                              ,(TLS.HashSHA1,   SignatureDSS)
                              ]

knownHashSignatures13 :: [HashAndSignatureAlgorithm]
knownHashSignatures13 = filter compat knownHashSignatures
  where
    compat (h,s) = h /= TLS.HashSHA1 && s /= SignatureDSS && s /= SignatureRSA

arbitraryHashSignatures :: Version -> Gen [HashAndSignatureAlgorithm]
arbitraryHashSignatures v = sublistOf l
    where l = if v < TLS13 then knownHashSignatures else knownHashSignatures13

-- for performance reason P521, FFDHE6144, FFDHE8192 are not tested
knownGroups, knownECGroups, knownFFGroups :: [Group]
knownECGroups = [P256,P384,X25519,X448]
knownFFGroups = [FFDHE2048,FFDHE3072,FFDHE4096]
knownGroups   = knownECGroups ++ knownFFGroups

defaultECGroup :: Group
defaultECGroup = P256  -- same as defaultECCurve

otherKnownECGroups :: [Group]
otherKnownECGroups = filter (/= defaultECGroup) knownECGroups

arbitraryGroups :: Gen [Group]
arbitraryGroups = scale (min 5) $ listOf1 $ elements knownGroups

isCredentialDSA :: (CertificateChain, PrivKey) -> Bool
isCredentialDSA (_, PrivKeyDSA _) = True
isCredentialDSA _                 = False

arbitraryCredentialsOfEachType :: Gen [(CertificateChain, PrivKey)]
arbitraryCredentialsOfEachType = arbitraryCredentialsOfEachType' >>= shuffle

arbitraryCredentialsOfEachType' :: Gen [(CertificateChain, PrivKey)]
arbitraryCredentialsOfEachType' = do
    let (pubKey, privKey) = getGlobalRSAPair
        curveName = defaultECCurve
    (dsaPub, dsaPriv) <- arbitraryDSAPair
    (ecdsaPub, ecdsaPriv) <- arbitraryECDSAPair curveName
    (ed25519Pub, ed25519Priv) <- arbitraryEd25519Pair
    (ed448Pub, ed448Priv) <- arbitraryEd448Pair
    mapM (\(pub, priv) -> do
              cert <- arbitraryX509WithKey (pub, priv)
              return (CertificateChain [cert], priv)
         ) [ (PubKeyRSA pubKey, PrivKeyRSA privKey)
           , (PubKeyDSA dsaPub, PrivKeyDSA dsaPriv)
           , (toPubKeyEC curveName ecdsaPub, toPrivKeyEC curveName ecdsaPriv)
           , (PubKeyEd25519 ed25519Pub, PrivKeyEd25519 ed25519Priv)
           , (PubKeyEd448 ed448Pub, PrivKeyEd448 ed448Priv)
           ]

arbitraryCredentialsOfEachCurve :: Gen [(CertificateChain, PrivKey)]
arbitraryCredentialsOfEachCurve = arbitraryCredentialsOfEachCurve' >>= shuffle

arbitraryCredentialsOfEachCurve' :: Gen [(CertificateChain, PrivKey)]
arbitraryCredentialsOfEachCurve' = do
    ecdsaPairs <-
        mapM (\curveName -> do
                 (ecdsaPub, ecdsaPriv) <- arbitraryECDSAPair curveName
                 return (toPubKeyEC curveName ecdsaPub, toPrivKeyEC curveName ecdsaPriv)
             ) knownECCurves
    (ed25519Pub, ed25519Priv) <- arbitraryEd25519Pair
    (ed448Pub, ed448Priv) <- arbitraryEd448Pair
    mapM (\(pub, priv) -> do
              cert <- arbitraryX509WithKey (pub, priv)
              return (CertificateChain [cert], priv)
         ) $ [ (PubKeyEd25519 ed25519Pub, PrivKeyEd25519 ed25519Priv)
             , (PubKeyEd448 ed448Pub, PrivKeyEd448 ed448Priv)
             ] ++ ecdsaPairs

dhParamsGroup :: DHParams -> Maybe Group
dhParamsGroup params
    | params == ffdhe2048 = Just FFDHE2048
    | params == ffdhe3072 = Just FFDHE3072
    | otherwise           = Nothing

isCustomDHParams :: DHParams -> Bool
isCustomDHParams params = params == dhParams512

leafPublicKey :: CertificateChain -> Maybe PubKey
leafPublicKey (CertificateChain [])       = Nothing
leafPublicKey (CertificateChain (leaf:_)) = Just (certPubKey $ getCertificate leaf)

isLeafRSA :: Maybe CertificateChain -> Bool
isLeafRSA chain = case chain >>= leafPublicKey of
                        Just (PubKeyRSA _) -> True
                        _                  -> False

arbitraryCipherPair :: Version -> Gen ([Cipher], [Cipher])
arbitraryCipherPair connectVersion = do
    serverCiphers      <- arbitraryCiphers `suchThat`
                                (\cs -> or [cipherAllowedForVersion connectVersion x | x <- cs])
    clientCiphers      <- arbitraryCiphers `suchThat`
                                (\cs -> or [x `elem` serverCiphers &&
                                            cipherAllowedForVersion connectVersion x | x <- cs])
    return (clientCiphers, serverCiphers)

arbitraryPairParams :: Gen (ClientParams, ServerParams)
arbitraryPairParams = elements knownVersions >>= arbitraryPairParamsAt

-- Pair of groups so that at least the default EC group P256 and one FF group
-- are in common.  This makes DHE and ECDHE ciphers always compatible with
-- extension "Supported Elliptic Curves" / "Supported Groups".
arbitraryGroupPair :: Gen ([Group], [Group])
arbitraryGroupPair = do
    (serverECGroups, clientECGroups) <- arbitraryGroupPairWith defaultECGroup otherKnownECGroups
    (serverFFGroups, clientFFGroups) <- arbitraryGroupPairFrom knownFFGroups
    serverGroups <- shuffle (serverECGroups ++ serverFFGroups)
    clientGroups <- shuffle (clientECGroups ++ clientFFGroups)
    return (clientGroups, serverGroups)
  where
    arbitraryGroupPairFrom list = elements list >>= \e ->
        arbitraryGroupPairWith e (filter (/= e) list)
    arbitraryGroupPairWith e es = do
        s <- sublistOf es
        c <- sublistOf es
        return (e : s, e : c)

arbitraryPairParams13 :: Gen (ClientParams, ServerParams)
arbitraryPairParams13 = arbitraryPairParamsAt TLS13

arbitraryPairParamsAt :: Version -> Gen (ClientParams, ServerParams)
arbitraryPairParamsAt connectVersion = do
    (clientCiphers, serverCiphers) <- arbitraryCipherPair connectVersion
    -- Select version lists containing connectVersion, as well as some other
    -- versions for which we have compatible ciphers.  Criteria about cipher
    -- ensure we can test version downgrade.
    let allowedVersions = [ v | v <- knownVersions,
                                or [ x `elem` serverCiphers &&
                                     cipherAllowedForVersion v x | x <- clientCiphers ]]
        allowedVersionsFiltered = filter (<= connectVersion) allowedVersions
    -- Server or client is allowed to have versions > connectVersion, but not
    -- both simultaneously.
    filterSrv <- arbitrary
    let (clientAllowedVersions, serverAllowedVersions)
            | filterSrv = (allowedVersions, allowedVersionsFiltered)
            | otherwise = (allowedVersionsFiltered, allowedVersions)
    -- Generate version lists containing less than 127 elements, otherwise the
    -- "supported_versions" extension cannot be correctly serialized
    clientVersions <- listWithOthers connectVersion 126 clientAllowedVersions
    serverVersions <- listWithOthers connectVersion 126 serverAllowedVersions
    arbitraryPairParamsWithVersionsAndCiphers (clientVersions, serverVersions) (clientCiphers, serverCiphers)
  where
    listWithOthers :: a -> Int -> [a] -> Gen [a]
    listWithOthers fixedElement maxOthers others
        | maxOthers < 1 = return [fixedElement]
        | otherwise     = sized $ \n -> do
            num <- choose (0, min n maxOthers)
            pos <- choose (0, num)
            prefix <- vectorOf pos $ elements others
            suffix <- vectorOf (num - pos) $ elements others
            return $ prefix ++ (fixedElement : suffix)

getConnectVersion :: (ClientParams, ServerParams) -> Version
getConnectVersion (cparams, sparams) = maximum (cver `intersect` sver)
  where
    sver = supportedVersions (serverSupported sparams)
    cver = supportedVersions (clientSupported cparams)

isVersionEnabled :: Version -> (ClientParams, ServerParams) -> Bool
isVersionEnabled ver (cparams, sparams) =
    (ver `elem` supportedVersions (serverSupported sparams)) &&
    (ver `elem` supportedVersions (clientSupported cparams))

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

arbitraryClientCredential :: Version -> Gen Credential
arbitraryClientCredential SSL3 = do
    -- for SSL3 there is no EC but only RSA/DSA
    creds <- arbitraryCredentialsOfEachType'
    elements (take 2 creds) -- RSA and DSA, but not ECDSA, Ed25519 and Ed448
arbitraryClientCredential v | v < TLS12 = do
    -- for TLS10 and TLS11 there is no EdDSA but only RSA/DSA/ECDSA
    creds <- arbitraryCredentialsOfEachType'
    elements (take 3 creds) -- RSA, DSA and ECDSA, but not EdDSA
arbitraryClientCredential _    = arbitraryCredentialsOfEachType' >>= elements

arbitraryRSACredentialWithUsage :: [ExtKeyUsageFlag] -> Gen (CertificateChain, PrivKey)
arbitraryRSACredentialWithUsage usageFlags = do
    let (pubKey, privKey) = getGlobalRSAPair
    cert <- arbitraryX509WithKeyAndUsage usageFlags (PubKeyRSA pubKey, ())
    return (CertificateChain [cert], PrivKeyRSA privKey)

arbitraryEMSMode :: Gen (EMSMode, EMSMode)
arbitraryEMSMode = (,) <$> gen <*> gen
  where gen = elements [ NoEMS, AllowEMS, RequireEMS ]

setEMSMode :: (EMSMode, EMSMode) -> (ClientParams, ServerParams) -> (ClientParams, ServerParams)
setEMSMode (cems, sems) (clientParam, serverParam) = (clientParam', serverParam')
  where
    clientParam' = clientParam { clientSupported = (clientSupported clientParam)
                                   { supportedExtendedMasterSec = cems }
                               }
    serverParam' = serverParam { serverSupported = (serverSupported serverParam)
                                   { supportedExtendedMasterSec = sems }
                               }

readClientSessionRef :: (IORef mclient, IORef mserver) -> IO mclient
readClientSessionRef refs = readIORef (fst refs)

twoSessionRefs :: IO (IORef (Maybe client), IORef (Maybe server))
twoSessionRefs = (,) <$> newIORef Nothing <*> newIORef Nothing

-- | simple session manager to store one session id and session data for a single thread.
-- a Real concurrent session manager would use an MVar and have multiples items.
oneSessionManager :: IORef (Maybe (SessionID, SessionData)) -> SessionManager
oneSessionManager ref = SessionManager
    { sessionResume         = \myId     -> readIORef ref >>= maybeResume False myId
    , sessionResumeOnlyOnce = \myId     -> readIORef ref >>= maybeResume True myId
    , sessionEstablish      = \myId dat -> writeIORef ref $ Just (myId, dat)
    , sessionInvalidate     = \_        -> return ()
    }
  where
    maybeResume onlyOnce myId (Just (sid, sdata))
        | sid == myId = when onlyOnce (writeIORef ref Nothing) >> return (Just sdata)
    maybeResume _ _ _ = return Nothing

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

withDataPipe :: (ClientParams, ServerParams) -> (Context -> Chan result -> IO ()) -> (Chan start -> Context -> IO ()) -> ((start -> IO (), IO result) -> IO a) -> IO a
withDataPipe params tlsServer tlsClient cont = do
    -- initial setup
    pipe        <- newPipe
    _           <- runPipe pipe
    startQueue  <- newChan
    resultQueue <- newChan

    (cCtx, sCtx) <- newPairContext pipe params

    withAsync (E.catch (tlsServer sCtx resultQueue)
                       (printAndRaise "server" (serverSupported $ snd params))) $ \sAsync -> do
    withAsync (E.catch (tlsClient startQueue cCtx)
                       (printAndRaise "client" (clientSupported $ fst params))) $ \cAsync -> do

      let readResult = waitBoth cAsync sAsync >> readChan resultQueue
      cont (writeChan startQueue, readResult)

  where
        printAndRaise :: String -> Supported -> E.SomeException -> IO ()
        printAndRaise s supported e = do
            putStrLn $ s ++ " exception: " ++ show e ++
                            ", supported: " ++ show supported
            E.throwIO e

initiateDataPipe :: (ClientParams, ServerParams) -> (Context -> IO a1) -> (Context -> IO a) -> IO (Either E.SomeException a, Either E.SomeException a1)
initiateDataPipe params tlsServer tlsClient = do
    -- initial setup
    pipe        <- newPipe
    _           <- runPipe pipe

    (cCtx, sCtx) <- newPairContext pipe params

    async (tlsServer sCtx) >>= \sAsync ->
        async (tlsClient cCtx) >>= \cAsync -> do
            sRes <- waitCatch sAsync
            cRes <- waitCatch cAsync
            return (cRes, sRes)

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
