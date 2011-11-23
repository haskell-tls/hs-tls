{-# LANGUAGE ScopedTypeVariables, DeriveDataTypeable #-}

import Network.TLS
import Network.TLS.Extra

import Data.Char
import Data.IORef

import System.IO
import Control.Monad
import Prelude hiding (catch)

import qualified Crypto.Random.AESCtr as RNG

import Text.Printf

import System.Console.CmdArgs

openConnection s p = do
	ref <- newIORef Nothing
	rng <- RNG.makeSystem
	let params = defaultParams
		{ pCiphers           = ciphersuite_all
		, onCertificatesRecv = \l -> do
			modifyIORef ref (const $ Just l)
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
	} deriving (Show, Data, Typeable)

progArgs = PArgs
	{ destination = "localhost" &= help "destination address to connect to" &= typ "address"
	, port        = "443"       &= help "destination port to connect to" &= typ "port"
	, chain       = False       &= help "also output the chain of certificate used"
	, output      = "pem"       &= help "define the format of output (PEM by default)" &= typ "format"
	} &= summary "RetrieveCertificate remotely for SSL/TLS protocol"
	&= details
		[ "Retrieve the remote certificate and optionally its chain from a remote destination"
		]

showCert _ cert =
	putStrLn $ show cert

main = do
	a <- cmdArgs progArgs
	_ <- printf "connecting to %s on port %s ...\n" (destination a) (port a)

	certs <- openConnection (destination a) (port a)
	case (chain a) of
		True ->
			forM_ (zip [0..] certs) $ \(n, cert) -> do
				putStrLn ("###### Certificate " ++ show (n + 1) ++ " ######")
				showCert (output a) cert
		False ->
			showCert (output a) $ head certs
