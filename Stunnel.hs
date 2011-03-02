{-# LANGUAGE DeriveDataTypeable #-}
import Network.BSD
import Network.Socket
import System.IO
import System.IO.Error hiding (try)
import System.Console.CmdArgs

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import Control.Concurrent (forkIO)
import Control.Exception (finally, try, throw)
import Control.Monad (when, forever)

import Data.Char (isDigit)

import Data.Certificate.PEM
import Data.Certificate.X509
import qualified Data.Certificate.KeyRSA as KeyRSA
import qualified Crypto.Cipher.RSA as RSA

import Network.TLS.Crypto
import Network.TLS.Cipher
import Network.TLS.SRandom
import Network.TLS.Struct

import Network.TLS.Core
import qualified Network.TLS.Server as S

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

tlsclient :: Handle -> TLSCtx -> IO ()
tlsclient srchandle dsthandle = do
	hSetBuffering srchandle NoBuffering

	handshake dsthandle

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

getRandomGen :: IO SRandomGen
getRandomGen = makeSRandomGen >>= either (fail . show) (return . id)

tlsserver srchandle dsthandle = do
	hSetBuffering dsthandle NoBuffering

	handshake srchandle

	loopUntil $ do
		d <- S.recvData srchandle
		putStrLn ("received: " ++ show d)
		sendData srchandle (L.pack $ map (toEnum . fromEnum) "this is some data")
		hFlush (getHandle srchandle)
		return False
	putStrLn "end"

clientProcess certs handle dsthandle _ = do
	rng <- getRandomGen

	let serverstate = defaultParams
		{ pAllowedVersions = [SSL3,TLS10,TLS11]
		, pCiphers         = ciphers
		, pCertificates    = certs
		, pWantClientCert  = False
		}
	ctx <- server serverstate rng handle
	tlsserver ctx dsthandle
	--S.runTLSServer (tlsserver handle dsthandle) serverstate rng

readCertificate :: FilePath -> IO X509
readCertificate filepath = do
	content <- B.readFile filepath
	let certdata = case parsePEMCert content of
		Nothing -> error ("no valid certificate section")
		Just x  -> x
	let cert = case decodeCertificate $ L.fromChunks [certdata] of
		Left err -> error ("cannot decode certificate: " ++ err)
		Right x  -> x
	return cert

readPrivateKey :: FilePath -> IO PrivateKey
readPrivateKey filepath = do
	content <- B.readFile filepath
	let pkdata = case parsePEMKeyRSA content of
		Nothing -> error ("no valid RSA key section")
		Just x  -> L.fromChunks [x]
	let pk = case KeyRSA.decodePrivate pkdata of
		Left err -> error ("cannot decode key: " ++ err)
		Right x  -> PrivRSA $ RSA.PrivateKey
			{ RSA.private_sz   = fromIntegral $ KeyRSA.lenmodulus x
			, RSA.private_n    = KeyRSA.modulus x
			, RSA.private_d    = KeyRSA.private_exponant x
			, RSA.private_p    = KeyRSA.p1 x
			, RSA.private_q    = KeyRSA.p2 x
			, RSA.private_dP   = KeyRSA.exp1 x
			, RSA.private_dQ   = KeyRSA.exp2 x
			, RSA.private_qinv = KeyRSA.coef x
			}
	return pk

data Stunnel =
	  Client
		{ destinationType :: String
		, destination     :: String
		, sourceType      :: String
		, source          :: String }
	| Server
		{ destinationType :: String
		, destination     :: String
		, sourceType      :: String
		, source          :: String
		, certificate     :: FilePath
		, key             :: FilePath }
	deriving (Show, Data, Typeable)

clientOpts = Client
	{ destinationType = "tcp"             &= help "type of source (tcp, unix, fd)" &= typ "DESTTYPE"
	, destination     = "localhost:6061"  &= help "destination address influenced by destination type" &= typ "ADDRESS"
	, sourceType      = "tcp"             &= help "type of source (tcp, unix, fd)" &= typ "SOURCETYPE"
	, source          = "localhost:6060"  &= help "source address influenced by source type" &= typ "ADDRESS"
	}
	&= help "connect to a remote destination that use SSL/TLS"

serverOpts = Server
	{ destinationType = "tcp"             &= help "type of source (tcp, unix, fd)" &= typ "DESTTYPE"
	, destination     = "localhost:6060"  &= help "destination address influenced by destination type" &= typ "ADDRESS"
	, sourceType      = "tcp"             &= help "type of source (tcp, unix, fd)" &= typ "SOURCETYPE"
	, source          = "localhost:6061"  &= help "source address influenced by source type" &= typ "ADDRESS"
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
	      (\_ -> sClose sock >> error ("cannot open socket " ++ show sockaddr))
	return $ StunnelSocket sock

connectAddressDescription (AddrFD h1 h2) = do
	return $ StunnelFd h1 h2

listenAddressDescription (AddrSocket family sockaddr) = do
	sock <- socket family Stream defaultProtocol
	catch (bindSocket sock sockaddr >> listen sock 10 >> setSocketOption sock ReuseAddr 1)
	      (\_ -> sClose sock >> error ("cannot open socket " ++ show sockaddr))
	return $ StunnelSocket sock

listenAddressDescription (AddrFD _ _) = do
	error "cannot listen on fd"

doClient :: Stunnel -> IO ()
doClient pargs = do
	srcaddr <- getAddressDescription (sourceType pargs) (source pargs)
	dstaddr <- getAddressDescription (destinationType pargs) (destination pargs)

	let clientstate = defaultParams
		{ pConnectVersion = TLS10
		, pAllowedVersions = [ TLS10, TLS11 ]
		, pCiphers = ciphers
		, pCertificates = []
		}

	case srcaddr of
		AddrSocket _ _ -> do
			(StunnelSocket srcsocket) <- listenAddressDescription srcaddr
			forever $ do
				(s, _) <- accept srcsocket
				rng    <- getRandomGen
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
	cert    <- readCertificate $ certificate pargs
	pk      <- readPrivateKey $ key pargs
	srcaddr <- getAddressDescription (sourceType pargs) (source pargs)
	dstaddr <- getAddressDescription (destinationType pargs) (destination pargs)

	case srcaddr of
		AddrSocket _ _ -> do
			(StunnelSocket srcsocket) <- listenAddressDescription srcaddr
			forever $ do
				(s, addr) <- accept srcsocket
				srch <- socketToHandle s ReadWriteMode
				(StunnelSocket dst) <- connectAddressDescription dstaddr
				dsth <- socketToHandle dst ReadWriteMode
				_ <- forkIO $ finally
					(clientProcess [(cert, Just pk)] srch dsth addr >> return ())
					(hClose srch >> hClose dsth)
				return ()
		AddrFD _ _ -> error "bad error fd. not implemented"

main :: IO ()
main = do
	x <- cmdArgsRun mode
	case x of
		Client _ _ _ _     -> doClient x
		Server _ _ _ _ _ _ -> doServer x
