import Text.Printf
import Data.Word
import Test.QuickCheck
import Test.QuickCheck.Test

import Network.TLS.Struct
import Network.TLS.Packet
import Control.Monad
import System.IO

liftM6 f m1 m2 m3 m4 m5 m6 = do { x1 <- m1; x2 <- m2; x3 <- m3; x4 <- m4; x5 <- m5; x6 <- m6; return (f x1 x2 x3 x4 x5 x6) }

someWords8 :: Int -> Gen [Word8] 
someWords8 i = replicateM i (fromIntegral `fmap` (choose (0,255) :: Gen Int))

someWords16 :: Int -> Gen [Word16] 
someWords16 i = replicateM i (fromIntegral `fmap` (choose (0,65535) :: Gen Int))

instance Arbitrary Version where
	arbitrary = elements [ SSL2, SSL3, TLS10, TLS11, TLS12 ]

instance Arbitrary ProtocolType where
	arbitrary = elements
		[ ProtocolType_ChangeCipherSpec
		, ProtocolType_Alert
		, ProtocolType_Handshake
		, ProtocolType_AppData ]

instance Arbitrary Word8 where
	arbitrary = fromIntegral `fmap` (choose (0,255) :: Gen Int)

instance Arbitrary Word16 where
	arbitrary = fromIntegral `fmap` (choose (0,65535) :: Gen Int)

instance Arbitrary Header where
	arbitrary = do
		pt <- arbitrary
		ver <- arbitrary
		len <- arbitrary
		return $ Header pt ver len

instance Arbitrary ClientRandom where
	arbitrary = ClientRandom `fmap` someWords8 32

instance Arbitrary ServerRandom where
	arbitrary = ServerRandom `fmap` someWords8 32

instance Arbitrary Session where
	arbitrary = do
		i <- choose (1,2) :: Gen Int
		case i of
			1 -> return $ Session Nothing
			2 -> (Session . Just) `fmap` someWords8 32

arbitraryCiphersIDs :: Gen [Word16]
arbitraryCiphersIDs = choose (0,200) >>= someWords16

arbitraryCompressionIDs :: Gen [Word8]
arbitraryCompressionIDs = choose (0,200) >>= someWords8

instance Arbitrary Handshake where
	arbitrary = oneof
		[ liftM6 ClientHello arbitrary arbitrary arbitrary arbitraryCiphersIDs arbitraryCompressionIDs (return Nothing)
		, liftM6 ServerHello arbitrary arbitrary arbitrary arbitrary arbitrary (return Nothing)
		, return HelloRequest
		, return ServerHelloDone
		]

{- quickcheck property -}

prop_header_marshalling_id x = (decodeHeader $ encodeHeader x) == Right x
prop_handshake_marshalling_id x = (decodeHs $ encodeHandshake x) == Right x
	where
		decodeHs b = either (Left . id) (\(ty, bdata) -> decodeHandshake TLS10 ty bdata) $ decodeHandshakeHeader b

{- main -}
args = Args
	{ replay     = Nothing
	, maxSuccess = 500
	, maxDiscard = 2000
	, maxSize    = 500
	}

run_test n t = putStr ("  " ++ n ++ " ... ") >> hFlush stdout >> quickCheckWith args t

main = do
	run_test "marshalling header = id" prop_header_marshalling_id
	run_test "marshalling handshake = id" prop_handshake_marshalling_id
