module Main (main) where

import System.Process
import System.Posix.Process (getProcessID)
import System.Exit
import Text.Printf
import Control.Concurrent.Async
import Control.Concurrent.MVar

data Version = SSL3 | TLS10 | TLS11 | TLS12
    deriving (Show,Eq,Ord)

data Option = Everything
            | LowerBound Version
            | UpperBound Version
            | RangeBound Version Version
    deriving (Show,Eq)

userAgent = "--user-agent="
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
simpleClient :: Int -> String -> Maybe String -> Version -> IO (ExitCode, String, String)
simpleClient clientPort clientHost uri ver =
    readProcessWithExitCode "./debug/dist/build/tls-simpleclient/tls-simpleclient"
        ["-v", "--debug", "-O", "/dev/null", clientHost, show clientPort, "--uri", maybe "/" id uri, verString, "--user-agent=" ]
        ""
  where verString =
            case ver of
                SSL3  -> "--ssl3"
                TLS10 -> "--tls10"
                TLS11 -> "--tls11"
                TLS12 -> "--tls12"

data FailStatus = FailStatus
    { failName     :: String
    , failExitCode :: Int
    , failOut      :: String
    , failErr      :: String
    } deriving (Show,Eq)

data Result = Success String | Skipped String | Failure FailStatus
    deriving (Show,Eq)

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
    
    reallyRunOne ver = do
        (ec,out,err) <- simpleClient 443 url Nothing ver
        case ec of
            ExitSuccess   -> return $ Success (show ver)
--                putRow url "SUCCESS"
--                mapM_ (putStrLn . ((++) "  ")) $ lines out
--                mapM_ (putStrLn . ((++) "  ")) $ lines err
            ExitFailure r -> return $ Failure $ FailStatus (show ver) r out err
                --putRow url "FAILED"
                --mapM_ (putStrLn . ((++) "  ")) $ lines out

putRow n s =
    putStrLn (pad 64 n ++ " " ++ s)

pad n s
    | length s >= n = s
    | otherwise     = s ++ replicate (n - length s) ' '

printIndented txt = mapM_ (putStrLn . ((++) "  ")) $ lines txt

logFile pid = "TestClient." ++ show pid ++ ".log"

run pid l = do
    putStrLn $ ("log file : " ++ lfile)
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
            appendFile lfile ("### " ++ url ++ "  name=" ++ name ++ "\n" ++ out)

    lfile = logFile pid

    toStats :: [Result] -> ([String], [String], [FailStatus])
    toStats = foldl accumulate ([], [], [])
      where accumulate (success, skipped, errs) (Success n) = (n : success, skipped, errs)
            accumulate (success, skipped, errs) (Skipped n) = (success, n : skipped, errs)
            accumulate (success, skipped, errs) (Failure r) = (success, skipped, r:errs)
 
-- no better name ..
t2 :: b -> [a] -> [(a, b)]
t2 b = map (\x -> (x, b))

main = do
    pid <- getProcessID
    run pid $
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
