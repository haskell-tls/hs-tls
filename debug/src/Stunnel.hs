{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE ScopedTypeVariables #-}
import Network.BSD
import Network.Socket hiding (Debug)
import System.IO
import System.IO.Error (isEOFError)
import System.Console.GetOpt
import System.Environment (getArgs)
import System.Exit
import System.X509
import Data.X509.Validation

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Control.Concurrent (forkIO)
import Control.Concurrent.MVar
import Control.Exception (finally, throw, SomeException)
import qualified Control.Exception as E
import Control.Monad (when, forever)

import Data.Char (isDigit)
import Data.Default.Class

import Crypto.Random
import Network.TLS
import Network.TLS.Extra.Cipher

import qualified Crypto.PubKey.DH as DH ()

ciphers :: [Cipher]
ciphers =
    [ cipher_DHE_RSA_AES256_SHA256
    , cipher_DHE_RSA_AES128_SHA256
    , cipher_DHE_RSA_AES256_SHA1
    , cipher_DHE_RSA_AES128_SHA1
    , cipher_DHE_DSS_AES128_SHA1
    , cipher_DHE_DSS_AES256_SHA1
    , cipher_DHE_DSS_RC4_SHA1
    , cipher_AES128_SHA1
    , cipher_AES256_SHA1
    , cipher_RC4_128_MD5
    , cipher_RC4_128_SHA1
    ]

loopUntil :: Monad m => m Bool -> m ()
loopUntil f = f >>= \v -> if v then return () else loopUntil f

readOne h = do
    r <- E.try $ hWaitForInput h (-1)
    case r of
        Left err    -> if isEOFError err then return B.empty else throw err
        Right True  -> B.hGetNonBlocking h 4096
        Right False -> return B.empty

tlsclient :: Handle -> Context -> IO ()
tlsclient srchandle dsthandle = do
    hSetBuffering srchandle NoBuffering

    handshake dsthandle

    _ <- forkIO $ forever $ do
        dat <- recvData dsthandle
        putStrLn ("received " ++ show dat)
        B.hPut srchandle dat
    loopUntil $ do
        b <- readOne srchandle
        putStrLn ("sending " ++ show b)
        if B.null b
            then do
                bye dsthandle
                return True
            else do
                sendData dsthandle (L.fromChunks [b])
                return False
    return ()

tlsserver srchandle dsthandle = do
    hSetBuffering dsthandle NoBuffering

    handshake srchandle

    loopUntil $ do
        d <- recvData srchandle
        putStrLn ("received: " ++ show d)
        sendData srchandle (L.pack $ map (toEnum . fromEnum) "this is some data")
        return False
    putStrLn "end"

newtype MemSessionManager = MemSessionManager (MVar [(SessionID, SessionData)])

memSessionManager (MemSessionManager mvar) = SessionManager
    { sessionEstablish  = \sid sdata -> modifyMVar_ mvar (\l -> return $ (sid,sdata) : l)
    , sessionResume     = \sid       -> withMVar mvar (return . lookup sid)
    , sessionInvalidate = \_         -> return ()
    }

clientProcess dhParamsFile creds handle dsthandle dbg sessionStorage _ = do
    let logging = if not dbg
            then def
            else def { loggingPacketSent = putStrLn . ("debug: send: " ++)
                     , loggingPacketRecv = putStrLn . ("debug: recv: " ++)
                     }

    dhParams <- case dhParamsFile of
            Nothing   -> return Nothing
            Just file -> (Just . read) `fmap` readFile file

    let serverstate = def
            { serverSupported = def { supportedCiphers = ciphers }
            , serverShared    = def { sharedCredentials = creds
                                    , sharedSessionManager = maybe noSessionManager (memSessionManager . MemSessionManager) sessionStorage
                                    }
            , serverDHEParams = dhParams
            }

    ctx <- contextNew handle serverstate
    contextHookSetLogging ctx logging
    tlsserver ctx dsthandle

data StunnelAddr   =
      AddrSocket Family SockAddr
    | AddrFD Handle Handle

data StunnelHandle =
      StunnelSocket Socket
    | StunnelFd     Handle Handle

getAddressDescription :: Address -> IO StunnelAddr
getAddressDescription (Address "tcp" desc) = do
    let (s, p) = break ((==) ':') desc
    when (p == "") (error $ "missing port: expecting [source]:port got " ++ show desc)
    pn <- if and $ map isDigit $ drop 1 p
        then return $ fromIntegral $ (read (drop 1 p) :: Int)
        else do
            service <- getServiceByName (drop 1 p) "tcp"
            return $ servicePort service
    he <- getHostByName s
    return $ AddrSocket AF_INET (SockAddrInet pn (head $ hostAddresses he))

getAddressDescription (Address "unix" desc) = do
    return $ AddrSocket AF_UNIX (SockAddrUnix desc)

getAddressDescription (Address "fd" _) =
    return $ AddrFD stdin stdout

getAddressDescription a = error ("unrecognized source type (expecting tcp/unix/fd, got " ++ show a ++ ")")

connectAddressDescription (AddrSocket family sockaddr) = do
    sock <- socket family Stream defaultProtocol
    E.catch (connect sock sockaddr)
          (\(e :: SomeException) -> sClose sock >> error ("cannot open socket " ++ show sockaddr ++ " " ++ show e))
    return $ StunnelSocket sock

connectAddressDescription (AddrFD h1 h2) = do
    return $ StunnelFd h1 h2

listenAddressDescription (AddrSocket family sockaddr) = do
    sock <- socket family Stream defaultProtocol
    E.catch (bindSocket sock sockaddr >> listen sock 10 >> setSocketOption sock ReuseAddr 1)
          (\(e :: SomeException) -> sClose sock >> error ("cannot open socket " ++ show sockaddr ++ " " ++ show e))
    return $ StunnelSocket sock

listenAddressDescription (AddrFD _ _) = do
    error "cannot listen on fd"

doClient :: Address -> Address -> [Flag] -> IO ()
doClient source destination@(Address a _) flags = do
    srcaddr <- getAddressDescription source
    dstaddr <- getAddressDescription destination

    let logging =
            if not (Debug `elem` flags)
                then def
                else def { loggingPacketSent = putStrLn . ("debug: send: " ++)
                         , loggingPacketRecv = putStrLn . ("debug: recv: " ++)
                         }

    store <- getSystemCertificateStore
    let validateCache
           | NoCertValidation `elem` flags =
                ValidationCache (\_ _ _ -> return ValidationCachePass)
                                (\_ _ _ -> return ())
           | otherwise = def
    let clientstate = (defaultParamsClient a B.empty)
                        { clientSupported = def { supportedCiphers = ciphers }
                        , clientShared    = def { sharedCAStore = store, sharedValidationCache = validateCache }
                        }

    case srcaddr of
        AddrSocket _ _ -> do
            (StunnelSocket srcsocket) <- listenAddressDescription srcaddr
            forever $ do
                (s, _) <- accept srcsocket
                srch   <- socketToHandle s ReadWriteMode

                (StunnelSocket dst)  <- connectAddressDescription dstaddr

                dsth <- socketToHandle dst ReadWriteMode
                dstctx <- contextNew dsth clientstate
                contextHookSetLogging dstctx logging
                _    <- forkIO $ finally
                    (tlsclient srch dstctx)
                    (hClose srch >> hClose dsth)
                return ()
        AddrFD _ _ -> error "bad error fd. not implemented"

loadCred (cert, priv) = do
    putStrLn ("loading credential " ++ show cert ++ " : key=" ++ show priv)
    res <- credentialLoadX509 cert priv
    case res of
        Left _  -> putStrLn "ERR"
        Right _ -> putStrLn "OK"
    return res


doServer :: Address -> Address -> [Flag] -> IO ()
doServer source destination flags = do
    creds <- (either (error . show) Credentials . sequence) `fmap` mapM loadCred (zip (getCertificate flags) (getKey flags))
    srcaddr <- getAddressDescription source
    dstaddr <- getAddressDescription destination
    let dhParamsFile = getDHParams flags

    sessionStorage <- if NoSession `elem` flags then return Nothing else (Just `fmap` newMVar [])

    case srcaddr of
        AddrSocket _ _ -> do
            (StunnelSocket srcsocket) <- listenAddressDescription srcaddr
            forever $ do
                (s, addr) <- accept srcsocket
                srch <- socketToHandle s ReadWriteMode
                r <- connectAddressDescription dstaddr
                dsth <- case r of
                    StunnelFd _ _     -> return stdout
                    StunnelSocket dst -> socketToHandle dst ReadWriteMode

                _ <- forkIO $ finally
                    (clientProcess dhParamsFile creds srch dsth (Debug `elem` flags) sessionStorage addr >> return ())
                    (hClose srch >> (when (dsth /= stdout) $ hClose dsth))
                return ()
        AddrFD _ _ -> error "bad error fd. not implemented"

printUsage =
    putStrLn $ usageInfo "usage: tls-stunnel <mode> [opts]\n\n\tmode:\n\tclient\n\tserver\n\nclient options:\n" options

data Flag =
      Source String
    | Destination String
    | SourceType String
    | DestinationType String
    | Debug
    | Help
    | Certificate String
    | Key String
    | DHParams String
    | NoSession
    | NoCertValidation
    deriving (Show,Eq)

options :: [OptDescr Flag]
options =
    [ Option ['s']  ["source"]  (ReqArg Source "source") "source address influenced by source type"
    , Option ['d']  ["destination"] (ReqArg Destination "destination") "destination address influenced by destination type"
    , Option []     ["source-type"] (ReqArg SourceType "source-type") "type of source (tcp, unix, fd)"
    , Option []     ["destination-type"] (ReqArg DestinationType "source-type") "type of source (tcp, unix, fd)"
    , Option []     ["debug"]   (NoArg Debug) "debug the TLS protocol printing debugging to stdout"
    , Option ['h']  ["help"]    (NoArg Help) "request help"
    , Option []     ["certificate"] (ReqArg Certificate "certificate") "certificate file"
    , Option []     ["key"] (ReqArg Key "key") "certificate file"
    , Option []     ["dhparams"] (ReqArg DHParams "dhparams") "DH parameter file"
    , Option []     ["no-session"] (NoArg NoSession) "disable support for session"
    , Option []     ["no-cert-validation"] (NoArg NoCertValidation) "disable certificate validation"
    ]

data Address = Address String String
    deriving (Show,Eq)

defaultSource      = Address "tcp" "localhost:6060"
defaultDestination = Address "tcp" "localhost:6061"

getSource opts = foldl accf defaultSource opts
  where accf (Address t _) (Source s)     = Address t s
        accf (Address _ s) (SourceType t) = Address t s
        accf acc           _              = acc

getDestination opts = foldl accf defaultDestination opts
  where accf (Address t _) (Destination s)     = Address t s
        accf (Address _ s) (DestinationType t) = Address t s
        accf acc           _                   = acc

onNull defVal l | null l    = defVal
                | otherwise = l

getCertificate :: [Flag] -> [String]
getCertificate opts = reverse $ onNull ["certificate.pem"] $ foldl accf [] opts
  where accf acc (Certificate cert) = cert:acc
        accf acc _                  = acc

getKey opts = reverse $ onNull ["certificate.key"] $ foldl accf [] opts
  where accf acc (Key key) = key : acc
        accf acc _         = acc

getDHParams opts = foldl accf Nothing opts
  where accf _   (DHParams file) = Just file
        accf acc _               = acc

main :: IO ()
main = do
    args <- getArgs
    let (opts,other,errs) = getOpt Permute options args
    when (not $ null errs) $ do
        putStrLn $ show errs
        exitFailure

    when (Help `elem` opts) $ do
        printUsage
        exitSuccess

    let source      = getSource opts
        destination = getDestination opts

    case other of
        []         -> printUsage
        "client":_ -> doClient source destination opts
        "server":_ -> doServer source destination opts
        mode:_     -> error ("unknown mode " ++ show mode)
