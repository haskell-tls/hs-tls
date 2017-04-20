{-# LANGUAGE BangPatterns #-}
module Main where

import Connection
import Certificate
import PubKey
import Criterion.Main
import Control.Concurrent.Chan
import Network.TLS
import Data.X509
import Data.X509.Validation
import Data.Default.Class
import Data.IORef

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

recvDataNonNull :: Context -> IO B.ByteString
recvDataNonNull ctx = recvData ctx >>= \l -> if B.null l then recvDataNonNull ctx else return l

getParams :: Version -> Cipher -> (ClientParams, ServerParams)
getParams connectVer cipher = (cParams, sParams)
  where sParams = def { serverSupported = supported
                      , serverShared = def {
                          sharedCredentials = Credentials [ (CertificateChain [simpleX509 $ PubKeyRSA pubKey], PrivKeyRSA privKey) ]
                          }
                      }
        cParams = (defaultParamsClient "" B.empty)
            { clientSupported = supported
            , clientShared = def { sharedValidationCache = ValidationCache
                                        { cacheAdd = \_ _ _ -> return ()
                                        , cacheQuery = \_ _ _ -> return ValidationCachePass
                                        }
                                 }
            }
        supported = def { supportedCiphers = [cipher]
                        , supportedVersions = [connectVer]
                        }
        (pubKey, privKey) = getGlobalRSAPair

runTLSPipe :: (ClientParams, ServerParams)
           -> (Context -> Chan b -> IO ())
           -> (Chan a -> Context -> IO ())
           -> a
           -> IO b
runTLSPipe params tlsServer tlsClient d = do
    (startQueue, resultQueue) <- establishDataPipe params tlsServer tlsClient
    writeChan startQueue d
    readChan resultQueue

runTLSPipeSimple :: (ClientParams, ServerParams) -> B.ByteString -> IO B.ByteString
runTLSPipeSimple params bs = runTLSPipe params tlsServer tlsClient bs
  where tlsServer ctx queue = do
            handshake ctx
            d <- recvDataNonNull ctx
            writeChan queue d
            return ()
        tlsClient queue ctx = do
            handshake ctx
            d <- readChan queue
            sendData ctx (L.fromChunks [d])
            bye ctx
            return ()

benchConnection :: (ClientParams, ServerParams) -> B.ByteString -> String -> Benchmark
benchConnection params !d name = bench name . nfIO $ runTLSPipeSimple params d

benchResumption :: (ClientParams, ServerParams) -> B.ByteString -> String -> Benchmark
benchResumption params !d name = env initializeSession runResumption
  where
    initializeSession = do
        sessionRef <- newIORef Nothing
        let sessionManager = oneSessionManager sessionRef
            params1 = setPairParamsSessionManager sessionManager params
        _ <- runTLSPipeSimple params1 d

        Just sessionParams <- readIORef sessionRef
        let params2 = setPairParamsSessionResuming sessionParams params1
        newIORef params2

    runResumption paramsRef = bench name . nfIO $ do
        params2 <- readIORef paramsRef
        runTLSPipeSimple params2 d

main :: IO ()
main = defaultMain
    [ bgroup "connection"
        -- not sure the number actually make sense for anything. improve ..
        [ benchConnection (getParams SSL3 blockCipher) (B.replicate 256 0) "SSL3-256 bytes"
        , benchConnection (getParams TLS10 blockCipher) (B.replicate 256 0) "TLS10-256 bytes"
        , benchConnection (getParams TLS11 blockCipher) (B.replicate 256 0) "TLS11-256 bytes"
        , benchConnection (getParams TLS12 blockCipher) (B.replicate 256 0) "TLS12-256 bytes"
        ]
    , bgroup "resumption"
        [ benchResumption (getParams SSL3 blockCipher) (B.replicate 256 0) "SSL3-256 bytes"
        , benchResumption (getParams TLS10 blockCipher) (B.replicate 256 0) "TLS10-256 bytes"
        , benchResumption (getParams TLS11 blockCipher) (B.replicate 256 0) "TLS11-256 bytes"
        , benchResumption (getParams TLS12 blockCipher) (B.replicate 256 0) "TLS12-256 bytes"
        ]
    ]
