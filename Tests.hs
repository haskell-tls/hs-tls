{-# LANGUAGE CPP #-}

import Test.QuickCheck
import Test.QuickCheck.Test
import Test.Framework (defaultMain, testGroup, buildTest)
import Test.Framework.Providers.QuickCheck2 (testProperty)

import Tests.Certificate

import Data.Word
import Data.Certificate.X509

import qualified Data.ByteString as B
import Network.TLS.Cipher
import Network.TLS.Struct
import Network.TLS.Packet
import Control.Monad
import Control.Applicative
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
	arbitrary = Header <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary ClientRandom where
	arbitrary = ClientRandom <$> (genByteString 32)

instance Arbitrary ServerRandom where
	arbitrary = ServerRandom <$> (genByteString 32)

instance Arbitrary ClientKeyData where
	arbitrary = ClientKeyData <$> (genByteString 46)

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

instance Arbitrary Handshake where
	arbitrary = oneof
		[ ClientHello
			<$> arbitrary
			<*> arbitrary
			<*> arbitrary
			<*> arbitraryCiphersIDs
			<*> arbitraryCompressionIDs
			<*> (return [])
		, ServerHello
			<$> arbitrary
			<*> arbitrary
			<*> arbitrary
			<*> arbitrary
			<*> arbitrary
			<*> (return [])
		, liftM Certificates (resize 2 $ listOf $ arbitraryX509)
		, pure HelloRequest
		, pure ServerHelloDone
		, ClientKeyXchg <$> arbitrary <*> arbitrary
		--, liftM  ServerKeyXchg
		--, liftM3 CertRequest arbitrary (return Nothing) (return [])
		--, liftM CertVerify (return [])
		, Finished <$> (genByteString 12)
		]

{- quickcheck property -}

prop_header_marshalling_id x = (decodeHeader $ encodeHeader x) == Right x
prop_handshake_marshalling_id x = (decodeHs $ encodeHandshake x) == Right x
	where
		decodeHs b = either (Left . id) (uncurry (decodeHandshake cp) . head) $ decodeHandshakes b
		cp = CurrentParams { cParamsVersion = TLS10, cParamsKeyXchgType = CipherKeyExchange_RSA }

tests_marshalling = testGroup "Marshalling"
	[ testProperty "Header" prop_header_marshalling_id
	, testProperty "Handshake" prop_handshake_marshalling_id
	]

main = defaultMain
	[ tests_marshalling
	]
