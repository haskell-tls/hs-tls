{-# LANGUAGE CPP #-}
module Main (main) where

import System.Process
import System.Environment
import System.Posix.Process (getProcessID)
import System.Exit
import System.Timeout
import System.Directory
import System.Random
import Text.Printf
import Control.Applicative
import Control.Monad
import Control.Concurrent.Async
import Control.Concurrent.MVar
import Control.Concurrent
import Control.Exception

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Maybe
import System.IO

import qualified Data.ByteString.UTF8 as UTF8

data Version = SSL3 | TLS10 | TLS11 | TLS12 | TLS13
    deriving (Show,Eq,Ord)

data Option = Everything
            | LowerBound Version
            | UpperBound Version
            | RangeBound Version Version
    deriving (Show,Eq)

data CertValidation = NoCertValidation | CertValidation
    deriving (Eq)

-- 10 seconds
timeoutSeconds = 15 * 1000000

forkWait :: IO a -> IO (IO a)
forkWait a = do
  res <- newEmptyMVar
  _ <- mask $ \restore -> forkIO $ try (restore a) >>= putMVar res
  return (takeMVar res >>= either (\ex -> throwIO (ex :: SomeException)) return)

-- | Like 'System.Process.readProcessWithExitCode', but using 'ByteString'
readProcessWithExitCodeBinary
    :: FilePath                 -- ^ command to run
    -> [String]                 -- ^ any arguments
    -> ByteString               -- ^ standard input
    -> IO (ExitCode, ByteString, ByteString) -- ^ exitcode, stdout, stderr
readProcessWithExitCodeBinary cmd args input = mask $ \restore -> do
    (Just inh, Just outh, Just errh, pid) <-
        createProcess (proc cmd args){ std_in  = CreatePipe,
                                       std_out = CreatePipe,
                                       std_err = CreatePipe }
    flip onException
      (do hClose inh; hClose outh; hClose errh;
          terminateProcess pid; waitForProcess pid) $ restore $ do

      -- fork off a thread to start consuming stdout
      waitOut <- forkWait $ B.hGetContents outh

      -- fork off a thread to start consuming stderr
      waitErr <- forkWait $ B.hGetContents errh

      -- now write and flush any input
      unless (B.null input) $ do B.hPutStr inh input; hFlush inh
      hClose inh -- done with stdin

      -- wait on the output
      out <- waitOut
      err <- waitErr

      hClose outh
      hClose errh

      -- wait on the process
      ex <- waitForProcess pid

      return (ex, out, err)

removeSafe f = doesFileExist f >>= flip when (removeFile f)

untilFileExist iter readyFile
    | iter == 15000 = return ()
    | otherwise     = do
        threadDelay 1000
        b <- doesFileExist readyFile
        if b then return () else untilFileExist (iter+1) readyFile

userAgent = "--user-agent=haskell tls 1.2"
{-
  -v          --verbose                verbose output on stdout
  -d          --debug                  TLS debug output on stdout
              --io-debug               TLS IO debug output on stdout
  -s          --session                try to resume a session
  -O stdout   --output=stdout          output
  -t timeout  --timeout=timeout        timeout in milliseconds (2s by default)
              --no-validation          disable certificate validation
              --http1.1                use http1.1 instead of http1.0
              --ssl3                   use SSL 3.0
              --no-sni                 don't use server name indication
              --user-agent=user-agent  use a user agent
              --tls10                  use TLS 1.0
              --tls11                  use TLS 1.1
              --tls12                  use TLS 1.2
              --tls13                  use TLS 1.3 (default)
              --bogocipher=cipher-id   add a bogus cipher id for testing
  -x          --no-version-downgrade   do not allow version downgrade
              --uri=URI                optional URI requested by default /
  -h          --help                   request help
-}
simpleClient :: Int
             -> String
             -> Maybe String
             -> Version
             -> CertValidation
             -> Maybe (FilePath, FilePath)
             -> IO (ExitCode, ByteString, ByteString)
simpleClient clientPort clientHost uri ver certVal clientCert =
#ifdef USE_CABAL
    readProcessWithExitCodeBinary "./debug/dist/build/tls-simpleclient/tls-simpleclient"
        (["-v", "--debug", "-O", "/dev/null", clientHost, show clientPort, "--uri", maybe "/" id uri, verString, userAgent]
#else
    readProcessWithExitCodeBinary "stack"
        (["exec", "--", "tls-simpleclient", "-v", "--debug", "-O", "/dev/null", clientHost, show clientPort, "--uri", fromMaybe "/" uri, verString, userAgent]
#endif
         ++ if certVal == CertValidation then [] else ["--no-validation"]
         ++ maybe [] (\(f,v) -> ["--client-cert=" ++ f ++ ":" ++ v ]) clientCert
        ) B.empty
  where verString =
            case ver of
                SSL3  -> "--ssl3"
                TLS10 -> "--tls10"
                TLS11 -> "--tls11"
                TLS12 -> "--tls12"
                TLS13 -> "--tls13"

opensslServer :: String -> Int -> String -> String -> Version -> Bool -> Bool -> IO (ExitCode, ByteString, ByteString)
opensslServer readyFile port cert key ver useClientCert useDhe =
    readProcessWithExitCodeBinary "./test-scripts/openssl-server"
        ([show port, cert, key, verString ]
         ++ (if useClientCert then ["client-cert"] else [])
         ++ (if useDhe then ["dhe"] else [])
         ++ ["ready-file",readyFile]
        ) B.empty
  where verString =
            case ver of
                SSL3  -> "ssl-3.0"
                TLS10 -> "tls-1.0"
                TLS11 -> "tls-1.1"
                TLS12 -> "tls-1.2"
                _     -> error ("opensslServer: unsupported version: " ++ show ver)

data FailStatus = FailStatus
    { failName     :: String
    , failExitCode :: Int
    , failOut      :: String
    , failErr      :: String
    } deriving (Show,Eq)

data Result = Success String String | Skipped String | Failure FailStatus | Timeout String
    deriving (Show,Eq)

prettyResult (Success name out) =
    "SUCCESS " ++ name ++ "\n" ++ out
prettyResult (Skipped name) = "SKIPPED " ++ name ++ "\n"
prettyResult (Timeout name) = "TIMEOUT " ++ name ++ "\n"
prettyResult (Failure (FailStatus name ec out err)) =
    "FAILURE " ++ name ++ " exitcode=" ++ show ec ++ "\n" ++ out ++ "\n" ++ err

showResultStatus (Success _ _) = "SUCCESS"
showResultStatus (Skipped _) = "SKIPPED"
showResultStatus (Failure _) = "FAILURE"
showResultStatus (Timeout _) = "TIMEOUT"

wrapResult name f = do
    r <- timeout timeoutSeconds f
    case r of
        Just (ExitSuccess, out, err)   -> return $ Success name (UTF8.toString (out `B.append` err))
        Just (ExitFailure r, out, err) -> return $ Failure $ FailStatus name r (UTF8.toString out) (UTF8.toString err)
        Nothing                        -> return $ Timeout name

test :: String -> Option -> [IO Result]
test url opt =
    map runOne [SSL3, TLS10, TLS11, TLS12, TLS13]
  where
    runOne ver = if doesRun then reallyRunOne ver else return (Skipped (show ver))
      where
        doesRun = case opt of
            Everything       -> True
            UpperBound bound
                | ver > bound -> False
                | otherwise   -> True
            LowerBound bound
                | ver < bound -> False
                | otherwise   -> True
            RangeBound minB maxB
                | ver < minB || ver > maxB -> False
                | otherwise                -> True
    reallyRunOne ver = wrapResult (show ver) (simpleClient 443 url Nothing ver CertValidation Nothing)


putRow n s =
    putStrLn (pad 64 n ++ " " ++ s)

pad n s
    | length s >= n = s
    | otherwise     = s ++ replicate (n - length s) ' '

printIndented txt = mapM_ (putStrLn . ("  " ++)) $ lines txt

runAgainstServices logFile pid l = do
    term <- newMVar ()
    let withTerm f = withMVar term $ \() -> f
    mapConcurrently (runGroup withTerm) l
  where
    runGroup :: (IO () -> IO ()) -> (String, Option) -> IO ()
    runGroup withTerm (url, opt) = do
        r <- mapConcurrently id $ test url opt
        let (success, skipped, errs) = toStats r
        withTerm $
            if null errs
                then
                    putRow url "SUCCESS"
                else do
                    putRow url "FAILED"
                    mapM_ (\n -> putStr "  " >> putRow n "SUCCESS") success
                    mapM_ (\n -> putStr "  " >> putRow n "SKIPPED") skipped
                    mapM_ showErr errs
      where

        showErr (FailStatus name ec out err) = do
            putStr "  " >> putRow (name ++ " exitcode=" ++ show ec) "FAILED"
            appendFile logFile ("### " ++ url ++ "  name=" ++ name ++ "\n" ++ out ++ "\n" ++ err)

    toStats :: [Result] -> ([String], [String], [FailStatus])
    toStats = foldl accumulate ([], [], [])
      where accumulate (success, skipped, errs) (Success n _) = (n : success, skipped, errs)
            accumulate (success, skipped, errs) (Skipped n)   = (success, n : skipped, errs)
            accumulate (success, skipped, errs) (Failure r)   = (success, skipped, r:errs)
            accumulate (success, skipped, errs) (Timeout _)   = (success, skipped, errs)

-- no better name ..
t2 :: b -> [a] -> [(a, b)]
t2 b = map (\x -> (x, b))

data Cred = Cred
    { credGetType :: String
    , credGetCert :: String
    , credGetKey  :: String
    }

runLocal logFile pid = do
    putStrLn "running local test against OpenSSL"
    let combi = [ (ver, cert, dhe, serverCert)
                | ver  <- [SSL3, TLS10, TLS11, TLS12] -- no TLS13 yet for local
                , cert <- [Nothing, Just ("test-certs/client.crt", "test-certs/client.key") ]
                , dhe  <- [False,True]
                , serverCert <- [Cred "RSA" "test-certs/server.rsa.crt" "test-certs/server.rsa.key"
                                ,Cred "DSA" "test-certs/server.dsa.crt" "test-certs/server.dsa.key"]
                ]
    haveFailed <- filter (== False) <$> mapM runOne combi
    unless (null haveFailed) exitFailure
  where
    -- running between port 14000 and 16901
    pidToPort pid = 14000 + (fromIntegral pid `mod` 2901)

    runOne (ver,ccert,useDhe,serverCert)
      | not useDhe && credGetType serverCert == "DSA" =
        putRow hdr "SKIPPED" >> return True
      | otherwise = do
        --putStrLn hdr
        opensslResult <- newEmptyMVar
        r <- randomIO
        let readyFile = "openssl-server-" ++ show pid ++ "-" ++ show (r :: Int) ++ ".ready"
        removeSafe readyFile

        _ <- forkIO $ do
            let useClientCert = isJust ccert
            r <- wrapResult "openssl" (opensslServer readyFile (pidToPort pid) (credGetCert serverCert) (credGetKey serverCert) ver useClientCert useDhe)
            putMVar opensslResult r
            case r of
                Success _ _ -> return ()
                _           -> putStrLn ("openssl finished: " ++ showResultStatus r)
        untilFileExist 0 readyFile

        r  <- wrapResult "simpleclient" (simpleClient (pidToPort pid) "localhost" Nothing ver NoCertValidation ccert)
        r2 <- readMVar opensslResult

        removeSafe readyFile
        case r of
            Success _ _ -> putRow hdr "SUCCESS" >> return True
            _           -> putRow hdr "FAILED" >> appendFile logFile (hdr ++ "\n\n" ++ prettyResult r ++ "\n\n" ++ prettyResult r2 ++ "\n\n\n") >> return False
      where
        hdr = "version=" ++ show ver ++ " client-cert=" ++ maybe "NO" (const "YES") ccert ++ " DHE=" ++ show useDhe ++ " server-cert=" ++ credGetType serverCert

main = do
    args <- getArgs
    pid <- getProcessID
    let (logFile, doLocal) = case args of
                    []    -> ("TestClient." ++ show (fromIntegral pid) ++ ".log", False)
                    ["with-local"] -> ("TestClient." ++ show (fromIntegral pid) ++ ".log", True)
                    ("with-local":x:_) -> (x, True)
                    (x:_) -> (x, False)

    putStrLn ("log file : " ++ logFile)

    when doLocal $ runLocal logFile pid
    runAgainstServices logFile pid $
        -- Everything supported
        --t2 Everything [] ++
        -- SSL3 not supported
        t2 (RangeBound TLS10 TLS13)
            [ "www.facebook.com"
            , "www.google.com"
            , "www.udacity.com"
            ] ++
        t2 (RangeBound TLS10 TLS12)
            [ "mail.office365.com"
            ] ++
        t2 (RangeBound TLS12 TLS13)
            [ "developer.apple.com"
            , "www.github.com"
            ] ++
        t2 (RangeBound TLS12 TLS12)
            [ "login.live.com"
            , "www.coursera.org"
            ]
