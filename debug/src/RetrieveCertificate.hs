{-# OPTIONS_GHC -fno-warn-warnings-deprecations #-}

import Control.Exception
import qualified Data.ByteString.Char8 as B
import Data.Default (def)
import Data.IORef
import Data.PEM
import Data.X509 as X509
import Data.X509.Validation
import Network.Socket
import System.Console.GetOpt
import System.Environment
import System.Exit
import System.X509
import Text.Printf

import Network.TLS
import Network.TLS.Extra.Cipher

import Imports

openConnection :: String -> String -> IO CertificateChain
openConnection s p = do
    ref <- newIORef Nothing
    let params =
            (defaultParamsClient s (B.pack p))
                { clientSupported = def{supportedCiphers = ciphersuite_all}
                , clientShared = def{sharedValidationCache = noValidate}
                }

    -- ctx <- connectionClient s p params rng
    let hints = defaultHints{addrSocketType = Stream}
    addr : _ <- getAddrInfo (Just hints) (Just s) (Just p)

    sock <- bracketOnError
        (socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr))
        close
        $ \sock -> do
            connect sock $ addrAddress addr
            return sock
    ctx <- contextNew sock params

    contextHookSetCertificateRecv ctx $ \l -> writeIORef ref (Just l)

    _ <- handshake ctx
    bye ctx
    r <- readIORef ref
    case r of
        Nothing -> error "cannot retrieve any certificate"
        Just certs -> return certs
  where
    noValidate =
        ValidationCache
            (\_ _ _ -> return ValidationCachePass)
            (\_ _ _ -> return ())

data Flag
    = PrintChain
    | Format String
    | Verify
    | GetFingerprint
    | VerifyFQDN String
    | Help
    deriving (Show, Eq)

options :: [OptDescr Flag]
options =
    [ Option
        []
        ["chain"]
        (NoArg PrintChain)
        "output the chain of certificate used"
    , Option
        []
        ["format"]
        (ReqArg Format "format")
        "define the output format (full, pem, default: simple)"
    , Option
        []
        ["verify"]
        (NoArg Verify)
        "verify the chain received with the trusted system certificate"
    , Option [] ["fingerprint"] (NoArg GetFingerprint) "show fingerprint (SHA1)"
    , Option
        []
        ["verify-domain-name"]
        (ReqArg VerifyFQDN "fqdn")
        "verify the chain against a specific FQDN"
    , Option ['h'] ["help"] (NoArg Help) "request help"
    ]

showCert :: String -> SignedExact Certificate -> IO ()
showCert "pem" cert = B.putStrLn $ pemWriteBS pem
  where
    pem =
        PEM
            { pemName = "CERTIFICATE"
            , pemHeader = []
            , pemContent = encodeSignedObject cert
            }
showCert "full" cert = print cert
showCert _ signedCert = do
    putStrLn ("serial:   " ++ show (certSerial cert))
    putStrLn ("issuer:   " ++ show (certIssuerDN cert))
    putStrLn ("subject:  " ++ show (certSubjectDN cert))
    putStrLn
        ( "validity: "
            ++ show (fst $ certValidity cert)
            ++ " to "
            ++ show (snd $ certValidity cert)
        )
  where
    cert = getCertificate signedCert

printUsage :: IO ()
printUsage =
    putStrLn $
        usageInfo
            "usage: retrieve-certificate [opts] <hostname> [port]\n\n\t(port default to: 443)\noptions:\n"
            options

main :: IO ()
main = do
    args <- getArgs
    let (opts, other, errs) = getOpt Permute options args
    when (not $ null errs) $ do
        print errs
        exitFailure

    when (Help `elem` opts) $ do
        printUsage
        exitSuccess

    case other of
        [destination, port] -> doMain destination port opts
        [destination] -> doMain destination "443" opts
        _ -> printUsage >> exitFailure
  where
    outputFormat [] = "simple"
    outputFormat (Format s : _) = s
    outputFormat (_ : xs) = outputFormat xs

    getFQDN [] = Nothing
    getFQDN (VerifyFQDN fqdn : _) = Just fqdn
    getFQDN (_ : xs) = getFQDN xs

    doMain destination port opts = do
        _ <- printf "connecting to %s on port %s ...\n" destination port

        chain <- openConnection destination port
        let (CertificateChain certs) = chain
            format = outputFormat opts
            fqdn = getFQDN opts
        if PrintChain `elem` opts
            then forM_ (zip [0 ..] certs) $ \(n, cert) -> do
                putStrLn ("###### Certificate " ++ show (n + 1 :: Int) ++ " ######")
                showCert format cert
            else showCert format $ head certs

        let fingerprints = foldl (doFingerprint (head certs)) [] opts
        unless (null fingerprints) $ putStrLn "Fingerprints:"
        mapM_ (\(alg, fprint) -> putStrLn ("  " ++ alg ++ " = " ++ show fprint)) $
            concat fingerprints

        when (Verify `elem` opts) $ do
            store <- getSystemCertificateStore
            putStrLn "### certificate chain trust"
            let checks =
                    defaultChecks
                        { checkExhaustive = True
                        , checkFQHN = isJust fqdn
                        }
                servId = (fromMaybe "" fqdn, B.empty)
            reasons <- validate X509.HashSHA256 def checks store def servId chain
            unless (null reasons) $ do
                putStrLn "fail validation:"
                print reasons

    doFingerprint cert acc GetFingerprint =
        [ ("SHA1", getFingerprint cert X509.HashSHA1)
        , ("SHA256", getFingerprint cert X509.HashSHA256)
        , ("SHA512", getFingerprint cert X509.HashSHA512)
        ]
            : acc
    doFingerprint _ acc _ = acc
