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

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Control.Concurrent (forkIO)
import Control.Concurrent.MVar
import Control.Exception (finally, throw, SomeException)
import qualified Control.Exception as E
import Control.Monad (when, forever)

import Data.Char (isDigit)

import qualified Crypto.Random.AESCtr as RNG
import Network.TLS
import Network.TLS.Extra

ciphers :: [Cipher]
ciphers =
    [ cipher_AES128_SHA1
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

data MemSessionManager = MemSessionManager (MVar [(SessionID, SessionData)])

instance SessionManager MemSessionManager where
    sessionEstablish (MemSessionManager mvar) sid sdata = modifyMVar_ mvar (\l -> return $ (sid,sdata) : l)
    sessionResume (MemSessionManager mvar) sid          = withMVar mvar (return . lookup sid)
    sessionInvalidate (MemSessionManager mvar) _        = return ()

clientProcess certs handle dsthandle dbg sessionStorage _ = do
    rng <- RNG.makeSystem
    let logging = if not dbg
            then defaultLogging
            else defaultLogging { loggingPacketSent = putStrLn . ("debug: send: " ++)
                                , loggingPacketRecv = putStrLn . ("debug: recv: " ++)
                                }

    let serverstate = maybe id (setSessionManager . MemSessionManager) sessionStorage $ defaultParamsServer
                        { pAllowedVersions = [SSL3,TLS10,TLS11,TLS12]
                        , pCiphers         = ciphers
                        , pCertificates    = certs
                        , pLogging         = logging
                        }

    ctx <- contextNewOnHandle handle serverstate rng
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
    when (p == "") (error "missing port: expecting [source]:port")
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

getAddressDescription _  = error "unrecognized source type (expecting tcp/unix/fd)"

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

    let logging = if not (Debug `elem` flags) then defaultLogging else defaultLogging
                            { loggingPacketSent = putStrLn . ("debug: send: " ++)
                            , loggingPacketRecv = putStrLn . ("debug: recv: " ++)
                            }

    store <- getSystemCertificateStore
    let checks = defaultChecks (Just a)
    let crecv = if not (NoCertValidation `elem` flags)
                then certificateChecks checks store
                else certificateNoChecks
    let clientstate = defaultParamsClient { pConnectVersion = TLS10
                                          , pAllowedVersions = [TLS10,TLS11,TLS12]
                                          , pCiphers = ciphers
                                          , pCertificates = Nothing
                                          , pLogging = logging
                                          , onCertificatesRecv = crecv
                                          }

    case srcaddr of
        AddrSocket _ _ -> do
            (StunnelSocket srcsocket) <- listenAddressDescription srcaddr
            forever $ do
                (s, _) <- accept srcsocket
                rng    <- RNG.makeSystem
                srch   <- socketToHandle s ReadWriteMode

                (StunnelSocket dst)  <- connectAddressDescription dstaddr

                dsth <- socketToHandle dst ReadWriteMode
                dstctx <- contextNewOnHandle dsth clientstate rng
                _    <- forkIO $ finally
                    (tlsclient srch dstctx)
                    (hClose srch >> hClose dsth)
                return ()
        AddrFD _ _ -> error "bad error fd. not implemented"

doServer :: Address -> Address -> [Flag] -> IO ()
doServer source destination flags = do
    cert    <- fileReadCertificateChain $ getCertificate flags
    pk      <- fileReadPrivateKey $ getKey flags
    srcaddr <- getAddressDescription source
    dstaddr <- getAddressDescription destination

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
                    (clientProcess (Just (cert, Just pk)) srch dsth (Debug `elem` flags) sessionStorage addr >> return ())
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
    | NoSession
    | NoCertValidation
    deriving (Show,Eq)

options :: [OptDescr Flag]
options =
    [ Option ['s']  ["source"]  (ReqArg Source "source") "source address influenced by source type"
    , Option ['d']  ["destination"] (ReqArg Destination "destination") "destination address influenced by destination type"
    , Option []     ["source-type"] (ReqArg SourceType "source-type") "type of source (tcp, unix, fd)"
    , Option []     ["destination-type"] (ReqArg SourceType "source-type") "type of source (tcp, unix, fd)"
    , Option []     ["debug"]   (NoArg Debug) "debug the TLS protocol printing debugging to stdout"
    , Option ['h']  ["help"]    (NoArg Help) "request help"
    , Option []     ["certificate"] (ReqArg Certificate "certificate") "certificate file"
    , Option []     ["key"] (ReqArg Key "key") "certificate file"
    , Option []     ["no-session"] (NoArg NoSession) "disable support for session"
    , Option []     ["no-cert-validation"] (NoArg NoCertValidation) "disable certificate validation"
    ]

data Address = Address String String
    deriving (Show,Eq)

defaultSource      = Address "localhost:6060" "tcp"
defaultDestination = Address "localhost:6061" "tcp"

getSource opts = foldl accf defaultSource opts
  where accf (Address _ t) (Source s)     = Address s t
        accf (Address s _) (SourceType t) = Address s t
        accf acc           _              = acc

getDestination opts = foldl accf defaultDestination opts
  where accf (Address _ t) (Destination s)     = Address s t
        accf (Address s _) (DestinationType t) = Address s t
        accf acc           _                   = acc

getCertificate opts = foldl accf "certificate.pem" opts
  where accf _   (Certificate cert) = cert
        accf acc _                  = acc

getKey opts = foldl accf "certificate.key" opts
  where accf _   (Key key) = key
        accf acc _         = acc

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
