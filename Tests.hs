{-# LANGUAGE CPP #-}

import Test.QuickCheck
import Test.QuickCheck.Test

--import Tests.Certificate

import Data.Word
import Data.Certificate.X509

import qualified Data.ByteString as B
import Network.TLS.Struct
import Network.TLS.Packet
import Control.Monad
import Control.Applicative ((<$>))
import System.IO

genByteString :: Int -> Gen B.ByteString
genByteString i = B.pack <$> vector i

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
	arbitrary = liftM3 Header arbitrary arbitrary arbitrary

instance Arbitrary ClientRandom where
	arbitrary = liftM ClientRandom (genByteString 32)

instance Arbitrary ServerRandom where
	arbitrary = liftM ServerRandom (genByteString 32)

instance Arbitrary ClientKeyData where
	arbitrary = liftM ClientKeyData (genByteString 46)

instance Arbitrary Session where
	arbitrary = do
		i <- choose (1,2) :: Gen Int
		case i of
			1 -> return $ Session Nothing
			2 -> liftM (Session . Just) (genByteString 32)

arbitraryCiphersIDs :: Gen [Word16]
arbitraryCiphersIDs = choose (0,200) >>= vector

arbitraryCompressionIDs :: Gen [Word8]
arbitraryCompressionIDs = choose (0,200) >>= vector

instance Arbitrary CertificateType where
	arbitrary = elements
		[ CertificateType_RSA_Sign, CertificateType_DSS_Sign
		, CertificateType_RSA_Fixed_DH, CertificateType_DSS_Fixed_DH
		, CertificateType_RSA_Ephemeral_DH, CertificateType_DSS_Ephemeral_DH
		, CertificateType_fortezza_dms ]

-- we hardcode the pubkey for generated X509. at later stage this will be generated as well.
pubkey = PubKeyRSA (1,2,3)

instance Arbitrary Handshake where
	arbitrary = oneof
		[ liftM6 ClientHello arbitrary arbitrary arbitrary arbitraryCiphersIDs arbitraryCompressionIDs (return Nothing)
		, liftM6 ServerHello arbitrary arbitrary arbitrary arbitrary arbitrary (return Nothing)
		--, liftM Certificates (resize 2 $ listOf $ arbitraryX509 pubkey)
		, return HelloRequest
		, return ServerHelloDone
		, liftM2 ClientKeyXchg arbitrary arbitrary
		--, liftM  ServerKeyXchg
		--, liftM3 CertRequest arbitrary (return Nothing) (return [])
		--, liftM CertVerify (return [])
		, liftM Finished (vector 12)
		]

{- quickcheck property -}

prop_header_marshalling_id x = (decodeHeader $ encodeHeader x) == Right x
prop_handshake_marshalling_id x = (decodeHs $ encodeHandshake x) == Right x
	where
		decodeHs b = either (Left . id) (uncurry (decodeHandshake TLS10) . head) $ decodeHandshakes b

myQuickCheckArgs = stdArgs
	{ replay     = Nothing
	, maxSuccess = 500
	, maxDiscard = 2000
	, maxSize    = 500
	}

run_test n t =
	putStr ("  " ++ n ++ " ... ") >> hFlush stdout >> quickCheckWith myQuickCheckArgs t

liftM6 f m1 m2 m3 m4 m5 m6 = do { x1 <- m1; x2 <- m2; x3 <- m3; x4 <- m4; x5 <- m5; x6 <- m6; return (f x1 x2 x3 x4 x5 x6) }

main = do
	run_test "marshalling header = id" prop_header_marshalling_id
	run_test "marshalling handshake = id" prop_handshake_marshalling_id
