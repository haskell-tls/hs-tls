{-# OPTIONS_GHC -fno-warn-orphans #-}
module Marshalling
    ( someWords8
    , prop_header_marshalling_id
    , prop_handshake_marshalling_id
    , prop_handshake13_marshalling_id
    ) where

import Control.Monad
import Control.Applicative
import Test.Tasty.QuickCheck
import Network.TLS.Internal
import Network.TLS

import qualified Data.ByteString as B
import Data.Word
import Data.X509 (CertificateChain(..))
import Certificate

genByteString :: Int -> Gen B.ByteString
genByteString i = B.pack <$> vector i

instance Arbitrary Version where
    arbitrary = elements [ SSL2, SSL3, TLS10, TLS11, TLS12, TLS13 ]

instance Arbitrary ProtocolType where
    arbitrary = elements
            [ ProtocolType_ChangeCipherSpec
            , ProtocolType_Alert
            , ProtocolType_Handshake
            , ProtocolType_AppData ]

instance Arbitrary Header where
    arbitrary = Header <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary ClientRandom where
    arbitrary = ClientRandom <$> genByteString 32

instance Arbitrary ServerRandom where
    arbitrary = ServerRandom <$> genByteString 32

instance Arbitrary Session where
    arbitrary = do
        i <- choose (1,2) :: Gen Int
        case i of
            2 -> Session . Just <$> genByteString 32
            _ -> return $ Session Nothing

instance Arbitrary HashAlgorithm where
    arbitrary = elements
        [ Network.TLS.HashNone
        , Network.TLS.HashMD5
        , Network.TLS.HashSHA1
        , Network.TLS.HashSHA224
        , Network.TLS.HashSHA256
        , Network.TLS.HashSHA384
        , Network.TLS.HashSHA512
        , Network.TLS.HashIntrinsic
        ]

instance Arbitrary SignatureAlgorithm where
    arbitrary = elements
        [ SignatureAnonymous
        , SignatureRSA
        , SignatureDSS
        , SignatureECDSA
        , SignatureRSApssRSAeSHA256
        , SignatureRSApssRSAeSHA384
        , SignatureRSApssRSAeSHA512
        , SignatureEd25519
        , SignatureEd448
        , SignatureRSApsspssSHA256
        , SignatureRSApsspssSHA384
        , SignatureRSApsspssSHA512
        ]

instance Arbitrary DigitallySigned where
    arbitrary = DigitallySigned Nothing <$> genByteString 32

arbitraryCiphersIDs :: Gen [Word16]
arbitraryCiphersIDs = choose (0,200) >>= vector

arbitraryCompressionIDs :: Gen [Word8]
arbitraryCompressionIDs = choose (0,200) >>= vector

someWords8 :: Int -> Gen [Word8]
someWords8 = vector

instance Arbitrary ExtensionRaw where
    arbitrary =
        let arbitraryContent = choose (0,40) >>= genByteString
         in ExtensionRaw <$> arbitrary <*> arbitraryContent

arbitraryHelloExtensions :: Version -> Gen [ExtensionRaw]
arbitraryHelloExtensions ver
    | ver >= SSL3 = arbitrary
    | otherwise   = return []  -- no hello extension with SSLv2

instance Arbitrary CertificateType where
    arbitrary = elements
            [ CertificateType_RSA_Sign, CertificateType_DSS_Sign
            , CertificateType_RSA_Fixed_DH, CertificateType_DSS_Fixed_DH
            , CertificateType_RSA_Ephemeral_DH, CertificateType_DSS_Ephemeral_DH
            , CertificateType_fortezza_dms ]

instance Arbitrary Handshake where
    arbitrary = oneof
            [ arbitrary >>= \ver -> ClientHello ver
                <$> arbitrary
                <*> arbitrary
                <*> arbitraryCiphersIDs
                <*> arbitraryCompressionIDs
                <*> arbitraryHelloExtensions ver
                <*> return Nothing
            , arbitrary >>= \ver -> ServerHello ver
                <$> arbitrary
                <*> arbitrary
                <*> arbitrary
                <*> arbitrary
                <*> arbitraryHelloExtensions ver
            , Certificates . CertificateChain <$> resize 2 (listOf arbitraryX509)
            , pure HelloRequest
            , pure ServerHelloDone
            , ClientKeyXchg . CKX_RSA <$> genByteString 48
            --, liftM  ServerKeyXchg
            , liftM3 CertRequest arbitrary (return Nothing) (listOf arbitraryDN)
            , CertVerify <$> arbitrary
            , Finished <$> genByteString 12
            ]

arbitraryCertReqContext :: Gen B.ByteString
arbitraryCertReqContext = oneof [ return B.empty, genByteString 32 ]

instance Arbitrary Handshake13 where
    arbitrary = oneof
            [ arbitrary >>= \ver -> ClientHello13 ver
                <$> arbitrary
                <*> arbitrary
                <*> arbitraryCiphersIDs
                <*> arbitraryHelloExtensions ver
            , arbitrary >>= \ver -> ServerHello13
                <$> arbitrary
                <*> arbitrary
                <*> arbitrary
                <*> arbitraryHelloExtensions ver
            , NewSessionTicket13
                <$> arbitrary
                <*> arbitrary
                <*> genByteString 32 -- nonce
                <*> genByteString 32 -- session ID
                <*> arbitrary
            , pure EndOfEarlyData13
            , EncryptedExtensions13 <$> arbitrary
            , CertRequest13
                <$> arbitraryCertReqContext
                <*> arbitrary
            , resize 2 (listOf arbitraryX509) >>= \certs -> Certificate13
                <$> arbitraryCertReqContext
                <*> return (CertificateChain certs)
                <*> replicateM (length certs) arbitrary
            , CertVerify13 <$> arbitrary <*> genByteString 32
            , Finished13 <$> genByteString 12
            , KeyUpdate13 <$> elements [ UpdateNotRequested, UpdateRequested ]
            ]

{- quickcheck property -}

prop_header_marshalling_id :: Header -> Bool
prop_header_marshalling_id x = decodeHeader (encodeHeader x) == Right x

prop_handshake_marshalling_id :: Handshake -> Bool
prop_handshake_marshalling_id x = decodeHs (encodeHandshake x) == Right x
  where decodeHs b = verifyResult (decodeHandshake cp) $ decodeHandshakeRecord b
        cp = CurrentParams { cParamsVersion = TLS10, cParamsKeyXchgType = Just CipherKeyExchange_RSA }

prop_handshake13_marshalling_id :: Handshake13 -> Bool
prop_handshake13_marshalling_id x = decodeHs (encodeHandshake13 x) == Right x
  where decodeHs b = verifyResult decodeHandshake13 $ decodeHandshakeRecord13 b

verifyResult :: (t -> b -> r) -> GetResult (t, b) -> r
verifyResult fn result =
    case result of
        GotPartial _ -> error "got partial"
        GotError e   -> error ("got error: " ++ show e)
        GotSuccessRemaining _ _ -> error "got remaining byte left"
        GotSuccess (ty, content) -> fn ty content
