{-# LANGUAGE BangPatterns #-}
module Main where

import Connection
import Certificate
import PubKey
import Gauge.Main
import Control.Concurrent.Chan
import Network.TLS
import Network.TLS.Extra.Cipher
import Data.X509
import Data.X509.Validation
import Data.Default.Class
import Data.IORef

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

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
        , bulkF         = BulkBlockF $ \ _ _ _ m -> (m, B.empty)
        }
    , cipherHash        = MD5
    , cipherPRFHash     = Nothing
    , cipherKeyExchange = CipherKeyExchange_RSA
    , cipherMinVer      = Nothing
    }

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
                        , supportedGroups = [X25519, FFDHE2048]
                        }
        (pubKey, privKey) = getGlobalRSAPair

runTLSPipe :: (ClientParams, ServerParams)
           -> (Context -> Chan b -> IO ())
           -> (Chan a -> Context -> IO ())
           -> a
           -> IO b
runTLSPipe params tlsServer tlsClient d = do
    withDataPipe params tlsServer tlsClient $ \(writeStart, readResult) -> do
        writeStart d
        readResult

runTLSPipeSimple :: (ClientParams, ServerParams) -> B.ByteString -> IO B.ByteString
runTLSPipeSimple params = runTLSPipe params tlsServer tlsClient
  where tlsServer ctx queue = do
            handshake ctx
            d <- recvData ctx
            writeChan queue d
            bye ctx
        tlsClient queue ctx = do
            handshake ctx
            d <- readChan queue
            sendData ctx (L.fromChunks [d])
            byeBye ctx

benchConnection :: (ClientParams, ServerParams) -> B.ByteString -> String -> Benchmark
benchConnection params !d name = bench name . nfIO $ runTLSPipeSimple params d

benchResumption :: (ClientParams, ServerParams) -> B.ByteString -> String -> Benchmark
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

benchResumption13 :: (ClientParams, ServerParams) -> B.ByteString -> String -> Benchmark
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
main = defaultMain
    [ bgroup "connection"
        -- not sure the number actually make sense for anything. improve ..
        [ benchConnection (getParams SSL3 blockCipher) small "SSL3-256 bytes"
        , benchConnection (getParams TLS10 blockCipher) small "TLS10-256 bytes"
        , benchConnection (getParams TLS11 blockCipher) small "TLS11-256 bytes"
        , benchConnection (getParams TLS12 blockCipher) small "TLS12-256 bytes"
        ]
    , bgroup "resumption"
        [ benchResumption (getParams SSL3 blockCipher) small "SSL3-256 bytes"
        , benchResumption (getParams TLS10 blockCipher) small "TLS10-256 bytes"
        , benchResumption (getParams TLS11 blockCipher) small "TLS11-256 bytes"
        , benchResumption (getParams TLS12 blockCipher) small "TLS12-256 bytes"
        ]
    -- Here we try to measure TLS12 and TLS13 performance with AEAD ciphers.
    -- Resumption and a larger message can be a demonstration of the symmetric
    -- crypto but for TLS13 this does not work so well because of dhe_psk.
    , benchCiphers "TLS12" TLS12 large
        [ cipher_DHE_RSA_AES128GCM_SHA256
        , cipher_DHE_RSA_AES256GCM_SHA384
        , cipher_DHE_RSA_CHACHA20POLY1305_SHA256
        , cipher_DHE_RSA_AES128CCM_SHA256
        , cipher_DHE_RSA_AES128CCM8_SHA256
        , cipher_ECDHE_RSA_AES128GCM_SHA256
        , cipher_ECDHE_RSA_AES256GCM_SHA384
        , cipher_ECDHE_RSA_CHACHA20POLY1305_SHA256
        ]
    , benchCiphers "TLS13" TLS13 large
        [ cipher_TLS13_AES128GCM_SHA256
        , cipher_TLS13_AES256GCM_SHA384
        , cipher_TLS13_CHACHA20POLY1305_SHA256
        , cipher_TLS13_AES128CCM_SHA256
        , cipher_TLS13_AES128CCM8_SHA256
        ]
    ]
  where
    small = B.replicate 256 0
    large = B.replicate 102400 0
