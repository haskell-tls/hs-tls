{-# LANGUAGE ScopedTypeVariables, DeriveDataTypeable, ViewPatterns #-}

import Network.TLS
import Network.TLS.Extra

import Data.IORef
import Data.Time.Clock
import Data.Certificate.X509
import System.Certificate.X509

import Control.Monad

import qualified Crypto.Random.AESCtr as RNG

import Text.Printf
import Text.Groom

import System.Console.CmdArgs

openConnection s p = do
    ref <- newIORef Nothing
    rng <- RNG.makeSystem
    let params = defaultParamsClient { pCiphers           = ciphersuite_all
                                     , onCertificatesRecv = \l -> do modifyIORef ref (const $ Just l)
                                                                     return CertificateUsageAccept
                                     }
    ctx <- connectionClient s p params rng
    _   <- handshake ctx
    bye ctx
    r <- readIORef ref
    case r of
        Nothing    -> error "cannot retrieve any certificate"
        Just certs -> return certs

data PArgs = PArgs
    { destination :: String
    , port        :: String
    , chain       :: Bool
    , output      :: String
    , verify      :: Bool
    , verifyFQDN  :: String
    } deriving (Show, Data, Typeable)

progArgs = PArgs
    { destination = "localhost" &= help "destination address to connect to" &= typ "address"
    , port        = "443"       &= help "destination port to connect to" &= typ "port"
    , chain       = False       &= help "also output the chain of certificate used"
    , output      = "simple"    &= help "define the format of output (full, pem, default: simple)" &= typ "format"
    , verify      = False       &= help "verify the chain received with the trusted system certificates"
    , verifyFQDN  = ""          &= help "verify the chain against a specific fully qualified domain name (e.g. web.example.com)" &= explicit &= name "verify-domain-name"
    } &= summary "RetrieveCertificate remotely for SSL/TLS protocol"
    &= details
        [ "Retrieve the remote certificate and optionally its chain from a remote destination"
        ]

showCert "full" cert = putStrLn $ groom cert

showCert _ (x509Cert -> cert)  = do
    putStrLn ("serial:   " ++ (show $ certSerial cert))
    putStrLn ("issuer:   " ++ (show $ certIssuerDN cert))
    putStrLn ("subject:  " ++ (show $ certSubjectDN cert))
    putStrLn ("validity: " ++ (show $ fst $ certValidity cert) ++ " to " ++ (show $ snd $ certValidity cert))

main = do
    a <- cmdArgs progArgs
    _ <- printf "connecting to %s on port %s ...\n" (destination a) (port a)

    certs <- openConnection (destination a) (port a)
    case (chain a) of
        True ->
            forM_ (zip [0..] certs) $ \(n, cert) -> do
                putStrLn ("###### Certificate " ++ show (n + 1 :: Int) ++ " ######")
                showCert (output a) cert
        False ->
            showCert (output a) $ head certs

    when (verify a) $ do
        store <- getSystemCertificateStore
        putStrLn "### certificate chain trust"
        ctime <- utctDay `fmap` getCurrentTime
        certificateVerifyChain store certs >>= showUsage "chain validity"
        showUsage "time validity" (certificateVerifyValidity ctime certs)
        when (verifyFQDN a /= "") $
            showUsage "fqdn match" (certificateVerifyDomain (verifyFQDN a) certs)
    where
        showUsage :: String -> TLSCertificateUsage -> IO ()
        showUsage s CertificateUsageAccept     = printf "%s : accepted\n" s
        showUsage s (CertificateUsageReject r) = printf "%s : rejected: %s\n" s (show r)
