{-# LANGUAGE ScopedTypeVariables, DeriveDataTypeable #-}

import Network.TLS.Internal
import Network.TLS.Cipher
import Network.TLS

import qualified Data.ByteString as B
import Data.Word
import Data.Char

import Network.Socket
import Network.BSD
import System.IO
import Control.Monad
import Control.Applicative ((<$>))
import Control.Concurrent
import Control.Exception (catch, SomeException(..))
import Prelude hiding (catch)

import Text.Printf

import System.Console.CmdArgs

fakeCipher cid = Cipher
	{ cipherID           = cid
	, cipherName         = "cipher-" ++ show cid
	, cipherDigestSize   = 0
	, cipherKeySize      = 0
	, cipherIVSize       = 0
	, cipherKeyBlockSize = 0
	, cipherPaddingSize  = 0
	, cipherKeyExchange  = CipherKeyExchangeRSA
	, cipherMACHash      = (\_ -> undefined)
	, cipherF            = undefined
	, cipherMinVer       = Nothing
	}

clienthello ciphers = ClientHello TLS10 (ClientRandom $ B.pack [0..31]) (Session Nothing) ciphers [0] Nothing

openConnection :: String -> String -> [Word16] -> IO (Maybe Word16)
openConnection s p ciphers = do
	pn     <- if and $ map isDigit $ p
			then return $ fromIntegral $ (read p :: Int)
			else do
				service <- getServiceByName p "tcp"
				return $ servicePort service
        he     <- getHostByName s
	sock   <- socket AF_INET Stream defaultProtocol
	connect sock (SockAddrInet pn (head $ hostAddresses he))
	handle <- socketToHandle sock ReadWriteMode

	(Right rng) <- makeSRandomGen
	let params = defaultParams { pCiphers = map fakeCipher ciphers }
	ctx <- client params rng handle
	sendPacket ctx $ Handshake $ clienthello ciphers
	catch (do
		rpkt <- recvPacket ctx
		ccid <- case rpkt of
			Right (h:_) -> case h of
				(Handshake (ServerHello _ _ _ i _ _)) -> return i
				_                                     -> error "didn't received serverhello"
			_                                           -> error ("packet received: " ++ show rpkt)
		bye ctx
		hClose handle
		return $ Just ccid
		) (\(_ :: SomeException) -> return Nothing)

connectRange :: String -> String -> Int -> [Word16] -> IO (Int, [Word16])
connectRange d p v r = do
	ccidopt <- openConnection d p r
	threadDelay v
	case ccidopt of
		Nothing   -> return (1, [])
		Just ccid -> do
			{-divide and conquer TLS-}
			let newr = filter ((/=) ccid) r
			let (lr, rr) = if length newr > 2
				then splitAt (length newr `div` 2) newr
				else (newr, [])
			(lc, ls) <- if length lr > 0
				then connectRange d p v lr 
				else return (0,[])
			(rc, rs) <- if length rr > 0
				then connectRange d p v rr
				else return (0,[])
			return (1 + lc + rc, [ccid] ++ ls ++ rs)

connectBetween d p v chunkSize ep sp = concat <$> loop sp where
	loop a = liftM2 (:) (snd <$> connectRange d p v range)
	                    (if a + chunkSize > ep then return [] else loop (a+64))
		where
			range = if a + chunkSize > ep
				then [a..ep]
				else [a..sp+chunkSize]

data PArgs = PArgs
	{ destination :: String
	, port        :: String
	, speed       :: Int
	, start       :: Int
	, end         :: Int
	, nb          :: Int
	} deriving (Show, Data, Typeable)

progArgs = PArgs
	{ destination = "localhost" &= help "destination address to connect to" &= typ "address"
	, port        = "443"       &= help "destination port to connect to" &= typ "port"
	, speed       = 100         &= help "speed between queries, in milliseconds" &= typ "speed"
	, start       = 0           &= help "starting cipher number (between 0 and 65535)" &= typ "cipher"
	, end         = 0xff        &= help "end cipher number (between 0 and 65535)" &= typ "cipher"
	, nb          = 64          &= help "number of cipher to include per query " &= typ "range"
	} &= summary "CheckCiphers -- SSL/TLS remotely check supported cipher"
	&= details
		[ "check the supported cipher of a remote destination."
		, "Beware: this program make multiple connections to the destination"
		, "which might be taken by the remote side as aggressive behavior"
		]

main = do
	a <- cmdArgs progArgs
	_ <- printf "connecting to %s on port %s ...\n" (destination a) (port a)
	supported <- connectBetween (destination a) (port a) (speed a) (fromIntegral $ nb a) (fromIntegral $ end a) (fromIntegral $ start a)
	putStrLn $ show supported
