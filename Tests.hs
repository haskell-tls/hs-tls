{-# LANGUAGE CPP #-}
import Text.Printf
import Data.Word
import Test.QuickCheck
import Test.QuickCheck.Test

import qualified Data.ByteString as B
import Network.TLS.Struct
import Network.TLS.Packet
import Control.Monad
import Control.Applicative ((<$>))
import System.IO

liftM6 f m1 m2 m3 m4 m5 m6 = do { x1 <- m1; x2 <- m2; x3 <- m3; x4 <- m4; x5 <- m5; x6 <- m6; return (f x1 x2 x3 x4 x5 x6) }

someWords8 :: Int -> Gen [Word8] 
someWords8 i = replicateM i (fromIntegral <$> (choose (0,255) :: Gen Int))

someWords16 :: Int -> Gen [Word16] 
someWords16 i = replicateM i (fromIntegral <$> (choose (0,65535) :: Gen Int))

instance Arbitrary Version where
	arbitrary = elements [ SSL2, SSL3, TLS10, TLS11, TLS12 ]

instance Arbitrary ProtocolType where
	arbitrary = elements
		[ ProtocolType_ChangeCipherSpec
		, ProtocolType_Alert
		, ProtocolType_Handshake
		, ProtocolType_AppData ]

#if MIN_VERSION_QuickCheck(2,3,0)
#else
instance Arbitrary Word8 where
	arbitrary = fromIntegral <$> (choose (0,255) :: Gen Int)

instance Arbitrary Word16 where
	arbitrary = fromIntegral <$> (choose (0,65535) :: Gen Int)
#endif

instance Arbitrary Header where
	arbitrary = do
		pt <- arbitrary
		ver <- arbitrary
		len <- arbitrary
		return $ Header pt ver len

instance Arbitrary ClientRandom where
	arbitrary = ClientRandom . B.pack <$> someWords8 32

instance Arbitrary ServerRandom where
	arbitrary = ServerRandom . B.pack <$> someWords8 32

instance Arbitrary ClientKeyData where
	arbitrary = ClientKeyData . B.pack <$> someWords8 46

instance Arbitrary Session where
	arbitrary = do
		i <- choose (1,2) :: Gen Int
		case i of
			1 -> return $ Session Nothing
			2 -> Session . Just . B.pack <$> someWords8 32

arbitraryCiphersIDs :: Gen [Word16]
arbitraryCiphersIDs = choose (0,200) >>= someWords16

arbitraryCompressionIDs :: Gen [Word8]
arbitraryCompressionIDs = choose (0,200) >>= someWords8

instance Arbitrary CertificateType where
	arbitrary = elements
		[ CertificateType_RSA_Sign, CertificateType_DSS_Sign
		, CertificateType_RSA_Fixed_DH, CertificateType_DSS_Fixed_DH
		, CertificateType_RSA_Ephemeral_dh, CertificateType_DSS_Ephemeral_dh
		, CertificateType_fortezza_dms ]

instance Arbitrary Handshake where
	arbitrary = oneof
		[ liftM6 ClientHello arbitrary arbitrary arbitrary arbitraryCiphersIDs arbitraryCompressionIDs (return Nothing)
		, liftM6 ServerHello arbitrary arbitrary arbitrary arbitrary arbitrary (return Nothing)
		, return (Certificates [])
		, return HelloRequest
		, return ServerHelloDone
		, liftM2 ClientKeyXchg arbitrary arbitrary
		--, liftM  ServerKeyXchg
		--, liftM3 CertRequest arbitrary (return Nothing) (return [])
		--, liftM CertVerify (return [])
		, liftM Finished (someWords8 12)
		]

{- quickcheck property -}

prop_header_marshalling_id x = (decodeHeader $ encodeHeader x) == Right x
prop_handshake_marshalling_id x = (decodeHs $ encodeHandshake x) == Right x
	where
		decodeHs b = either (Left . id) (uncurry (decodeHandshake TLS10) . head) $ decodeHandshakes b

{- main -}
args = Args
	{ replay     = Nothing
	, maxSuccess = 500
	, maxDiscard = 2000
	, maxSize    = 500
#if MIN_VERSION_QuickCheck(2,3,0)
	, chatty     = True
#endif
	}

run_test n t = putStr ("  " ++ n ++ " ... ") >> hFlush stdout >> quickCheckWith args t

main = do
	run_test "marshalling header = id" prop_header_marshalling_id
	run_test "marshalling handshake = id" prop_handshake_marshalling_id
