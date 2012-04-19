{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE ScopedTypeVariables #-}
import Network.BSD
import Network.Socket
import System.IO
import System.IO.Error hiding (try, catch)
import System.Console.CmdArgs

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Control.Concurrent (forkIO)
import Control.Concurrent.MVar
import Control.Exception (finally, try, throw, catch, SomeException)
import Control.Monad (when, forever)

import Data.Char (isDigit)

import qualified Crypto.Random.AESCtr as RNG
import Network.TLS
import Network.TLS.Extra

import Prelude hiding (catch)

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
	r <- try $ hWaitForInput h (-1)
	case r of
		Left err    -> if isEOFError err then return B.empty else throw err
		Right True  -> B.hGetNonBlocking h 4096
		Right False -> return B.empty

tlsclient :: Handle -> TLSCtx Handle -> IO ()
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
		hFlush (ctxConnection srchandle)
		return False
	putStrLn "end"

clientProcess certs handle dsthandle dbg sessionStorage _ = do
	rng <- RNG.makeSystem
	let logging = if not dbg then defaultLogging else defaultLogging
		{ loggingPacketSent = putStrLn . ("debug: send: " ++)
		, loggingPacketRecv = putStrLn . ("debug: recv: " ++)
		}

	let serverstate = defaultParams
		{ pAllowedVersions = [SSL3,TLS10,TLS11,TLS12]
		, pCiphers         = ciphers
		, pCertificates    = certs
		, pWantClientCert  = False
		, pLogging         = logging
		}
	let serverState' = case sessionStorage of
		Nothing      -> serverstate
		Just storage -> serverstate
			{ onSessionResumption  = \s -> withMVar storage (return . lookup s)
			, onSessionEstablished = \s d -> modifyMVar_ storage (\l -> return $ (s,d) : l)
			}

	ctx <- server serverState' rng handle
	tlsserver ctx dsthandle

data Stunnel =
	  Client
		{ destinationType :: String
		, destination     :: String
		, sourceType      :: String
		, source          :: String
		, debug           :: Bool
		, validCert       :: Bool }
	| Server
		{ destinationType :: String
		, destination     :: String
		, sourceType      :: String
		, source          :: String
		, debug           :: Bool
		, disableSession  :: Bool
		, certificate     :: FilePath
		, key             :: FilePath }
	deriving (Show, Data, Typeable)

clientOpts = Client
	{ destinationType = "tcp"             &= help "type of source (tcp, unix, fd)" &= typ "DESTTYPE"
	, destination     = "localhost:6061"  &= help "destination address influenced by destination type" &= typ "ADDRESS"
	, sourceType      = "tcp"             &= help "type of source (tcp, unix, fd)" &= typ "SOURCETYPE"
	, source          = "localhost:6060"  &= help "source address influenced by source type" &= typ "ADDRESS"
	, debug           = False             &= help "debug the TLS protocol printing debugging to stdout" &= typ "Bool"
	, validCert       = False             &= help "check if the certificate receive is valid" &= typ "Bool"
	}
	&= help "connect to a remote destination that use SSL/TLS"

serverOpts = Server
	{ destinationType = "tcp"             &= help "type of source (tcp, unix, fd)" &= typ "DESTTYPE"
	, destination     = "localhost:6060"  &= help "destination address influenced by destination type" &= typ "ADDRESS"
	, sourceType      = "tcp"             &= help "type of source (tcp, unix, fd)" &= typ "SOURCETYPE"
	, source          = "localhost:6061"  &= help "source address influenced by source type" &= typ "ADDRESS"
	, disableSession  = False             &= help "disable support for session" &= typ "Bool"
	, debug           = False             &= help "debug the TLS protocol printing debugging to stdout" &= typ "Bool"
	, certificate     = "certificate.pem" &= help "X509 public certificate to use" &= typ "FILE"
	, key             = "certificate.key" &= help "private key linked to the certificate" &= typ "FILE"
	}
	&= help "listen for connection that use SSL/TLS and relay it to a different connection"

mode = cmdArgsMode $ modes [clientOpts,serverOpts]
	&= help "create SSL/TLS tunnel in client or server mode" &= program "stunnel" &= summary "Stunnel v0.1 (Haskell TLS)"

data StunnelAddr   =
	  AddrSocket Family SockAddr
	| AddrFD Handle Handle

data StunnelHandle =
	  StunnelSocket Socket
	| StunnelFd     Handle Handle

getAddressDescription :: String -> String -> IO StunnelAddr
getAddressDescription "tcp"  desc = do
	let (s, p) = break ((==) ':') desc
	when (p == "") (error "missing port: expecting [source]:port")
	pn <- if and $ map isDigit $ drop 1 p
		then return $ fromIntegral $ (read (drop 1 p) :: Int)
		else do
			service <- getServiceByName (drop 1 p) "tcp"
			return $ servicePort service
	he <- getHostByName s
	return $ AddrSocket AF_INET (SockAddrInet pn (head $ hostAddresses he))

getAddressDescription "unix" desc = do
	return $ AddrSocket AF_UNIX (SockAddrUnix desc)

getAddressDescription "fd" _  =
	return $ AddrFD stdin stdout

getAddressDescription _ _  = error "unrecognized source type (expecting tcp/unix/fd)"

connectAddressDescription (AddrSocket family sockaddr) = do
	sock <- socket family Stream defaultProtocol
	catch (connect sock sockaddr)
	      (\(e :: SomeException) -> sClose sock >> error ("cannot open socket " ++ show sockaddr ++ " " ++ show e))
	return $ StunnelSocket sock

connectAddressDescription (AddrFD h1 h2) = do
	return $ StunnelFd h1 h2

listenAddressDescription (AddrSocket family sockaddr) = do
	sock <- socket family Stream defaultProtocol
	catch (bindSocket sock sockaddr >> listen sock 10 >> setSocketOption sock ReuseAddr 1)
	      (\(e :: SomeException) -> sClose sock >> error ("cannot open socket " ++ show sockaddr ++ " " ++ show e))
	return $ StunnelSocket sock

listenAddressDescription (AddrFD _ _) = do
	error "cannot listen on fd"

doClient :: Stunnel -> IO ()
doClient pargs = do
	srcaddr <- getAddressDescription (sourceType pargs) (source pargs)
	dstaddr <- getAddressDescription (destinationType pargs) (destination pargs)

	let logging = if not $ debug pargs then defaultLogging else defaultLogging
		{ loggingPacketSent = putStrLn . ("debug: send: " ++)
		, loggingPacketRecv = putStrLn . ("debug: recv: " ++)
		}

	let crecv = if validCert pargs then certificateVerifyChain else (\_ -> return CertificateUsageAccept)
	let clientstate = defaultParams
		{ pConnectVersion = TLS10
		, pAllowedVersions = [TLS10,TLS11,TLS12]
		, pCiphers = ciphers
		, pCertificates = []
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
				dstctx <- client clientstate rng dsth
				_    <- forkIO $ finally
					(tlsclient srch dstctx)
					(hClose srch >> hClose dsth)
				return ()
		AddrFD _ _ -> error "bad error fd. not implemented"

doServer :: Stunnel -> IO ()
doServer pargs = do
	cert    <- fileReadCertificate $ certificate pargs
	pk      <- fileReadPrivateKey $ key pargs
	srcaddr <- getAddressDescription (sourceType pargs) (source pargs)
	dstaddr <- getAddressDescription (destinationType pargs) (destination pargs)

	sessionStorage <- if disableSession pargs then return Nothing else (Just `fmap` newMVar [])

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
					(clientProcess [(cert, Just pk)] srch dsth (debug pargs) sessionStorage addr >> return ())
					(hClose srch >> (when (dsth /= stdout) $ hClose dsth))
				return ()
		AddrFD _ _ -> error "bad error fd. not implemented"

main :: IO ()
main = do
	x <- cmdArgsRun mode
	case x of
		Client {} -> doClient x
		Server {} -> doServer x
