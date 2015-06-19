module Connection
    ( newPairContext
    , arbitraryPairParams
    , setPairParamsSessionManager
    , setPairParamsSessionResuming
    , establishDataPipe
    , blockCipher
    , streamCipher
    ) where

import Test.Tasty.QuickCheck
import Certificate
import PubKey
import PipeChan
import Network.TLS
import Data.X509
import Data.Default.Class
import Control.Applicative
import Control.Concurrent.Chan
import Control.Concurrent
import qualified Control.Exception as E

import qualified Data.ByteString as B

debug = False

blockCipher :: Cipher
blockCipher = Cipher
    { cipherID   = 0xff12
    , cipherName = "rsa-id-const"
    , cipherBulk = Bulk
        { bulkName      = "id"
        , bulkKeySize   = 16
        , bulkIVSize    = 16
        , bulkBlockSize = 16
        , bulkF         = BulkBlockF $ \_ _ _ -> (\m -> (m, B.empty))
        }
    , cipherHash = MD5
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

streamCipher :: Cipher
streamCipher = blockCipher
    { cipherID   = 0xff13
    , cipherBulk = Bulk
        { bulkName      = "stream"
        , bulkKeySize   = 16
        , bulkIVSize    = 0
        , bulkBlockSize = 0
        , bulkF         = BulkStreamF passThrough
        }
    }
  where
    passThrough _ _ = BulkStream go where go inp = (inp, BulkStream go)

knownCiphers :: [Cipher]
knownCiphers = [blockCipher,blockCipherDHE_RSA,blockCipherDHE_DSS,streamCipher]

knownVersions :: [Version]
knownVersions = [SSL3,TLS10,TLS11,TLS12]

arbitraryPairParams = do
    (dsaPub, dsaPriv) <- (\(p,r) -> (PubKeyDSA p, PrivKeyDSA r)) <$> arbitraryDSAPair
    let (pubKey, privKey) = (\(p, r) -> (PubKeyRSA p, PrivKeyRSA r)) $ getGlobalRSAPair
    creds              <- mapM (\(pub, priv) -> do
                                    cert <- arbitraryX509WithKey (pub, priv)
                                    return (CertificateChain [cert], priv)
                               ) [ (pubKey, privKey), (dsaPub, dsaPriv) ]
    connectVersion     <- elements knownVersions
    let allowedVersions = [ v | v <- knownVersions, v <= connectVersion ]
    serAllowedVersions <- (:[]) `fmap` elements allowedVersions
    serverCiphers      <- arbitraryCiphers
    clientCiphers      <- oneof [arbitraryCiphers] `suchThat` (\cs -> or [x `elem` serverCiphers | x <- cs])
    secNeg             <- arbitrary


    let serverState = def
            { serverSupported = def { supportedCiphers  = serverCiphers
                                    , supportedVersions = serAllowedVersions
                                    , supportedSecureRenegotiation = secNeg
                                    }
            , serverDHEParams = Just dhParams
            , serverShared = def { sharedCredentials = Credentials creds }
            }
    let clientState = (defaultParamsClient "" B.empty)
            { clientSupported = def { supportedCiphers  = clientCiphers
                                    , supportedVersions = allowedVersions
                                    , supportedSecureRenegotiation = secNeg
                                    }
            , clientShared = def { sharedValidationCache = ValidationCache
                                        { cacheAdd = \_ _ _ -> return ()
                                        , cacheQuery = \_ _ _ -> return ValidationCachePass
                                        }
                                }
            }
    return (clientState, serverState)
  where
        arbitraryCiphers  = resize (length knownCiphers + 1) $ listOf1 (elements knownCiphers)

setPairParamsSessionManager :: SessionManager -> (ClientParams, ServerParams) -> (ClientParams, ServerParams)
setPairParamsSessionManager manager (clientState, serverState) = (nc,ns)
  where nc = clientState { clientShared = updateSessionManager $ clientShared clientState }
        ns = serverState { serverShared = updateSessionManager $ serverShared serverState }
        updateSessionManager shared = shared { sharedSessionManager = manager }

setPairParamsSessionResuming sessionStuff (clientState, serverState) =
    ( clientState { clientWantSessionResume = Just sessionStuff }
    , serverState)

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

establishDataPipe params tlsServer tlsClient = do
    -- initial setup
    pipe        <- newPipe
    _           <- (runPipe pipe)
    startQueue  <- newChan
    resultQueue <- newChan

    (cCtx, sCtx) <- newPairContext pipe params

    _ <- forkIO $ E.catch (tlsServer sCtx resultQueue) (printAndRaise "server")
    _ <- forkIO $ E.catch (tlsClient startQueue cCtx) (printAndRaise "client")

    return (startQueue, resultQueue)
  where
        printAndRaise :: String -> E.SomeException -> IO ()
        printAndRaise s e = putStrLn (s ++ " exception: " ++ show e) >> E.throw e
