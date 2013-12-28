{-# LANGUAGE BangPatterns #-}
module Main where

import Connection
import Certificate
import PubKey
import Criterion.Main
import Control.Concurrent.Chan
import Network.TLS
import Data.X509

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

recvDataNonNull ctx = recvData ctx >>= \l -> if B.null l then recvDataNonNull ctx else return l

getParams connectVer cipher = (cParams, sParams)
  where sParams = defaultParamsServer
            { pAllowedVersions = [connectVer]
            , pConnectVersion  = connectVer
            , pCiphers         = [cipher]
            , pCredentials     = Credentials [ (CertificateChain [simpleX509 $ PubKeyRSA pubKey], PrivKeyRSA privKey) ]
            }
        cParams = defaultParamsClient
            { pAllowedVersions = [connectVer]
            , pConnectVersion  = connectVer
            , pCiphers         = [cipher]
            }
        (pubKey, privKey) = getGlobalRSAPair

runTLSPipe params tlsServer tlsClient d name = bench name $ do
    (startQueue, resultQueue) <- establishDataPipe params tlsServer tlsClient
    writeChan startQueue d
    readChan resultQueue

bench1 params !d name = runTLSPipe params tlsServer tlsClient d name
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

main = defaultMain
    [ bgroup "connection"
        -- not sure the number actually make sense for anything. improve ..
        [ bench1 (getParams SSL3 blockCipher) (B.replicate 256 0) "SSL3-256 bytes"
        , bench1 (getParams TLS10 blockCipher) (B.replicate 256 0) "TLS10-256 bytes"
        , bench1 (getParams TLS11 blockCipher) (B.replicate 256 0) "TLS11-256 bytes"
        , bench1 (getParams TLS12 blockCipher) (B.replicate 256 0) "TLS12-256 bytes"
        ]
    ]
