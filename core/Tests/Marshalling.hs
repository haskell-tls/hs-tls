{-# LANGUAGE CPP #-}
module Marshalling where

import Control.Monad
import Control.Applicative
import Test.Tasty.QuickCheck
import Network.TLS.Internal
import Network.TLS
import qualified Network.TLS.Extension as EX

import qualified Data.ByteString as B
import Data.Word
import Data.X509
import Certificate

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

instance Arbitrary Header where
    arbitrary = Header <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary ClientRandom where
    arbitrary = ClientRandom <$> (genByteString 32)

instance Arbitrary ServerRandom where
    arbitrary = ServerRandom <$> (genByteString 32)

instance Arbitrary Session where
    arbitrary = do
        i <- choose (1,2) :: Gen Int
        case i of
            2 -> liftM (Session . Just) (genByteString 32)
            _ -> return $ Session Nothing

instance Arbitrary DigitallySigned where
    arbitrary = DigitallySigned Nothing <$> genByteString 32

arbitraryCiphersIDs :: Gen [Word16]
arbitraryCiphersIDs = choose (0,200) >>= vector

arbitraryCompressionIDs :: Gen [Word8]
arbitraryCompressionIDs = choose (0,200) >>= vector

someWords8 :: Int -> Gen [Word8]
someWords8 i = replicateM i (fromIntegral <$> (choose (0,255) :: Gen Int))

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
                <*> (return Nothing)
            , ServerHello
                <$> arbitrary
                <*> arbitrary
                <*> arbitrary
                <*> arbitrary
                <*> arbitrary
                <*> (return [])
            , liftM Certificates (CertificateChain <$> (resize 2 $ listOf $ arbitraryX509))
            , pure HelloRequest
            , pure ServerHelloDone
            , ClientKeyXchg . CKX_RSA <$> genByteString 48
            --, liftM  ServerKeyXchg
            , liftM3 CertRequest arbitrary (return Nothing) (return [])
            , CertVerify <$> arbitrary
            , Finished <$> (genByteString 12)
            ]

instance Arbitrary EX.ServerNameType where
  arbitrary = EX.ServerNameHostName <$> arbitrary

instance Arbitrary EX.ServerName where
  arbitrary = EX.ServerName <$> arbitrary

{- quickcheck property -}

prop_header_marshalling_id :: Header -> Bool
prop_header_marshalling_id x = (decodeHeader $ encodeHeader x) == Right x

prop_handshake_marshalling_id :: Handshake -> Bool
prop_handshake_marshalling_id x = (decodeHs $ encodeHandshake x) == Right x
  where decodeHs b = case decodeHandshakeRecord b of
                        GotPartial _ -> error "got partial"
                        GotError e   -> error ("got error: " ++ show e)
                        GotSuccessRemaining _ _ -> error "got remaining byte left"
                        GotSuccess (ty, content) -> decodeHandshake cp ty content
        cp = CurrentParams { cParamsVersion = TLS10, cParamsKeyXchgType = Just CipherKeyExchange_RSA, cParamsSupportNPN = True }

prop_disallow_empty_hostname :: EX.ServerName -> Bool
prop_disallow_empty_hostname x = case decoded of
  Just (EX.ServerName ns) -> all checkname ns
  Nothing -> False
  where
    decoded = EX.extensionDecode False . EX.extensionEncode $ x
    checkname (EX.ServerNameHostName n) = not $ null n
    checkname _ = False
