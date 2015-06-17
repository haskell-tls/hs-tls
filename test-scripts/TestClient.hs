module Main (main) where

import System.Process
import System.Environment
import System.Posix.Process (getProcessID)
import System.Exit
import System.Timeout
import Text.Printf
import Control.Applicative
import Control.Monad
import Control.Concurrent.Async
import Control.Concurrent.MVar
import Control.Concurrent
import Control.Exception

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import System.IO

import qualified Data.ByteString.UTF8 as UTF8

data Version = SSL3 | TLS10 | TLS11 | TLS12
    deriving (Show,Eq,Ord)

data Option = Everything
            | LowerBound Version
            | UpperBound Version
            | RangeBound Version Version
    deriving (Show,Eq)

data CertValidation = NoCertValidation | CertValidation
    deriving (Eq)

-- 10 seconds
timeoutSeconds = 10 * 1000000

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
              --tls12                  use TLS 1.2 (default)
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
    readProcessWithExitCodeBinary "./debug/dist/build/tls-simpleclient/tls-simpleclient"
        (["-v", "--debug", "-O", "/dev/null", clientHost, show clientPort, "--uri", maybe "/" id uri, verString, userAgent]
         ++ if certVal == CertValidation then [] else ["--no-validation"]
         ++ maybe [] (\(f,v) -> ["--client-cert=" ++ f ++ ":" ++ v ]) clientCert
        ) B.empty
  where verString =
            case ver of
                SSL3  -> "--ssl3"
                TLS10 -> "--tls10"
                TLS11 -> "--tls11"
                TLS12 -> "--tls12"

opensslServer :: Int -> String -> String -> Version -> Bool -> IO (ExitCode, ByteString, ByteString)
opensslServer port cert key ver useClientCert =
    readProcessWithExitCodeBinary "./test-scripts/openssl-server"
        ([show port, cert, key, verString ]
         ++ if useClientCert then ["client-cert"] else []
        ) B.empty
  where verString =
            case ver of
                SSL3  -> "ssl-3.0"
                TLS10 -> "tls-1.0"
                TLS11 -> "tls-1.1"
                TLS12 -> "tls-1.2"

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
test url opt = do
    map runOne [SSL3, TLS10, TLS11, TLS12]
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

printIndented txt = mapM_ (putStrLn . ((++) "  ")) $ lines txt

runAgainstServices logFile pid l = do
    term <- newMVar ()
    let withTerm f = withMVar term $ \() -> f
    mapConcurrently (runGroup withTerm) l
  where
    runGroup :: (IO () -> IO ()) -> (String, Option) -> IO ()
    runGroup withTerm (url, opt) = do
        r <- mapConcurrently id $ test url opt
        let (success, skipped, errs) = toStats r
        withTerm $ do
            if null errs
                then do
                    putRow url "SUCCESS"
                else do
                    putRow url "FAILED"
                    mapM_ (\n -> putStr "  " >> putRow n "SUCCESS") success
                    mapM_ (\n -> putStr "  " >> putRow n "SKIPPED") skipped
                    mapM_ showErr errs
      where

        showErr (FailStatus name ec out err) = do
            putStr "  " >> putRow (name ++ " exitcode=" ++ show ec) "FAILED"
            appendFile logFile ("### " ++ url ++ "  name=" ++ name ++ "\n" ++ out)

    toStats :: [Result] -> ([String], [String], [FailStatus])
    toStats = foldl accumulate ([], [], [])
      where accumulate (success, skipped, errs) (Success n _) = (n : success, skipped, errs)
            accumulate (success, skipped, errs) (Skipped n)   = (success, n : skipped, errs)
            accumulate (success, skipped, errs) (Failure r)   = (success, skipped, r:errs)

-- no better name ..
t2 :: b -> [a] -> [(a, b)]
t2 b = map (\x -> (x, b))

runLocal logFile pid = do
    putStrLn "running local test against OpenSSL"
    let combi = [ (ver, cert)
                | ver  <- [SSL3, TLS10, TLS11, TLS12]
                , cert <- [Nothing, Just ("test-certs/client.crt", "test-certs/client.key") ]
                ]
    haveFailed <- filter (== False) <$> mapM runOne combi
    when (not $ null haveFailed) $ exitFailure
  where
    -- running between port 14000 and 16901
    pidToPort pid = 14000 + (fromIntegral pid `mod` 2901)

    runOne (ver,ccert) = do
        let hdr = "version=" ++ show ver ++ " client-certificate: " ++ maybe "NO" (const "YES") ccert
        putStrLn hdr
        opensslResult <- newEmptyMVar
        _ <- forkIO $ do
            let useClientCert = maybe False (const True) ccert
            r <- wrapResult "openssl" (opensslServer (pidToPort pid) "test-certs/server.rsa.crt" "test-certs/server.rsa.key" ver useClientCert)
            putMVar opensslResult r
            case r of
                Success _ _ -> return ()
                _           -> putStrLn ("openssl finished: " ++ showResultStatus r)
        -- FIXME : racy. replace by a check that the port is bound
        threadDelay 800000
        r  <- wrapResult "simpleclient" (simpleClient (pidToPort pid) "localhost" Nothing ver NoCertValidation ccert)
        r2 <- readMVar opensslResult
        case r of
            Success _ _ -> putRow "" "SUCCESS" >> return True
            _           -> putRow "" "FAILED" >> appendFile logFile (hdr ++ "\n\n" ++ prettyResult r ++ "\n\n" ++ prettyResult r2 ++ "\n\n\n") >> return False

main = do
    args <- getArgs
    pid <- getProcessID
    let logFile = case args of
                    []    -> "TestClient." ++ show (fromIntegral pid) ++ ".log"
                    (x:_) -> x

    putStrLn $ ("log file : " ++ logFile)

    runLocal logFile pid
    runAgainstServices logFile pid $
        -- Everything supported
        t2 Everything
            [ "www.google.com"
            , "www.udacity.com"
            , "www.coursera.org"
            ] ++
        -- SSL3 not supported
        t2 (LowerBound TLS10)
            [ "developer.apple.com"
            , "www.facebook.com"
            , "www.github.com"
            , "mail.office365.com"
            , "login.live.com"
            ]
