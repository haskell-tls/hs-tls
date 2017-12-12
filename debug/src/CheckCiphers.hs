{-# LANGUAGE DeriveDataTypeable #-}

import Control.Concurrent
import Control.Exception (SomeException(..))
import qualified Control.Exception as E
import qualified Crypto.Random.AESCtr as RNG
import qualified Data.ByteString as B
import Data.Char
import Network.BSD
import Network.Socket
import System.IO
import Text.Printf

import Network.TLS
import Network.TLS.Cipher
import Network.TLS.Internal

import Imports

tableCiphers =
    [ (0x0000, "NULL_WITH_NULL_NULL")
    , (0x0001, "RSA_WITH_NULL_MD5")
    , (0x0002, "RSA_WITH_NULL_SHA")
    , (0x003B, "RSA_WITH_NULL_SHA256")
    , (0x0004, "RSA_WITH_RC4_128_MD5")
    , (0x0005, "RSA_WITH_RC4_128_SHA")
    , (0x000A, "RSA_WITH_3DES_EDE_CBC_SHA")
    , (0x002F, "RSA_WITH_AES_128_CBC_SHA")
    , (0x0035, "RSA_WITH_AES_256_CBC_SHA")
    , (0x003C, "RSA_WITH_AES_128_CBC_SHA256")
    , (0x003D, "RSA_WITH_AES_256_CBC_SHA256")
    , (0x000D, "DH_DSS_WITH_3DES_EDE_CBC_SHA")
    , (0x0010, "DH_RSA_WITH_3DES_EDE_CBC_SHA")
    , (0x0013, "DHE_DSS_WITH_3DES_EDE_CBC_SHA")
    , (0x0016, "DHE_RSA_WITH_3DES_EDE_CBC_SHA")
    , (0x0030, "DH_DSS_WITH_AES_128_CBC_SHA")
    , (0x0031, "DH_RSA_WITH_AES_128_CBC_SHA")
    , (0x0032, "DHE_DSS_WITH_AES_128_CBC_SHA")
    , (0x0033, "DHE_RSA_WITH_AES_128_CBC_SHA")
    , (0x0036, "DH_DSS_WITH_AES_256_CBC_SHA")
    , (0x0037, "DH_RSA_WITH_AES_256_CBC_SHA")
    , (0x0038, "DHE_DSS_WITH_AES_256_CBC_SHA")
    , (0x0039, "DHE_RSA_WITH_AES_256_CBC_SHA")
    , (0x003E, "DH_DSS_WITH_AES_128_CBC_SHA256")
    , (0x003F, "DH_RSA_WITH_AES_128_CBC_SHA256")
    , (0x0040, "DHE_DSS_WITH_AES_128_CBC_SHA256")
    , (0x0067, "DHE_RSA_WITH_AES_128_CBC_SHA256")
    , (0x0068, "DH_DSS_WITH_AES_256_CBC_SHA256")
    , (0x0069, "DH_RSA_WITH_AES_256_CBC_SHA256")
    , (0x006A, "DHE_DSS_WITH_AES_256_CBC_SHA256")
    , (0x006B, "DHE_RSA_WITH_AES_256_CBC_SHA256")
    , (0x0018, "DH_anon_WITH_RC4_128_MD5")
    , (0x001B, "DH_anon_WITH_3DES_EDE_CBC_SHA")
    , (0x0034, "DH_anon_WITH_AES_128_CBC_SHA")
    , (0x003A, "DH_anon_WITH_AES_256_CBC_SHA")
    , (0x006C, "DH_anon_WITH_AES_128_CBC_SHA256")
    , (0x006D, "DH_anon_WITH_AES_256_CBC_SHA256")
    ]

fakeCipher cid = Cipher
    { cipherID           = cid
    , cipherName         = "cipher-" ++ show cid
    , cipherBulk         = Bulk
        { bulkName         = "fake"
        , bulkKeySize      = 0
        , bulkIVSize       = 0
        , bulkBlockSize    = 0
        , bulkF            = undefined
        }
    , cipherKeyExchange  = CipherKeyExchange_RSA
    , cipherHash         = Hash
        { hashName = "fake"
        , hashSize = 0
        , hashF    = undefined
        }
    , cipherMinVer       = Nothing
    }

clienthello ciphers = ClientHello TLS10 (ClientRandom $ B.pack [0..31]) (Session Nothing) ciphers [0] [] Nothing

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

    rng <- RNG.makeSystem
    let params = defaultParamsClient { pCiphers = map fakeCipher ciphers }
    ctx <- contextNewOnHandle handle params rng
    sendPacket ctx $ Handshake [clienthello ciphers]
    E.catch (do
        rpkt <- recvPacket ctx
        ccid <- case rpkt of
            Right (Handshake ((ServerHello _ _ _ i _ _):_)) -> return i
            _                                               -> error ("expecting server hello, packet received: " ++ show rpkt)
        bye ctx
        hClose handle
        return $ Just ccid
        ) (\(SomeException _) -> return Nothing)

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

{-
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
-}

main = do
    putStrLn "broken"
{-
    _ <- printf "connecting to %s on port %s ...\n" (destination a) (port a)
    supported <- connectBetween (destination a) (port a) (speed a) (fromIntegral $ nb a) (fromIntegral $ end a) (fromIntegral $ start a)
    forM_ supported $ \i -> do
        putStrLn $ maybe ("cipher " ++ show i) id $ lookup i tableCiphers
-}
