{-# LANGUAGE OverloadedStrings #-}

module Main where

import Crypto.HPKE (
    AEAD_ID (..),
    EncodedPublicKey (..),
    EncodedSecretKey (..),
    KDF_ID (..),
    KEM_ID (..),
 )
import Crypto.HPKE.Internal (defaultHPKEMap, genKeyPair)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import Data.Word (Word8)
import Network.TLS.ECH.Config
import System.Environment

kemId :: KEM_ID
kemId = DHKEM_X25519_HKDF_SHA256

kdfId :: KDF_ID
kdfId = HKDF_SHA256

aeadId :: AEAD_ID
aeadId = AES_128_GCM

mkConfig
    :: Word8
    -> String
    -> KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> EncodedServerPublicKey
    -> ECHConfig
mkConfig confid hostname kemid kdfid aeadid pkm =
    ECHConfig
        { contents =
            ECHConfigContents
                { key_config =
                    HpkeKeyConfig
                        { config_id = confid
                        , kem_id = fromKEM_ID kemid
                        , public_key = pkm
                        , cipher_suites =
                            [ HpkeSymmetricCipherSuite
                                { kdf_id = fromKDF_ID kdfid
                                , aead_id = fromAEAD_ID aeadid
                                }
                            ]
                        }
                , maximum_name_length = 0
                , public_name = hostname
                , extensions = []
                }
        }

main :: IO ()
main = do
    args <- getArgs
    case args of
        [hostname, num] -> do
            let confId = read num :: Word8
            (EncodedPublicKey pkm, EncodedSecretKey skm) <-
                genKeyPair defaultHPKEMap kemId
            let config = mkConfig confId hostname kemId kdfId aeadId (EncodedServerPublicKey pkm)
                configs = [config]
            let encodedConfigList = encodeECHConfigList configs
            let encodedConfig = BS.drop 2 encodedConfigList
            print configs

            let configfileR = hostname ++ ".raw"
            BS.writeFile configfileR encodedConfigList

            let configfileO = hostname ++ ".one"
            BS.writeFile configfileO encodedConfig

            let configfileB = hostname ++ ".b64"
                configB64 = B64.encode encodedConfigList
            BS.writeFile configfileB configB64

            putStrLn "ECH config files:"
            putStrLn $
                "\t\""
                    ++ configfileR
                    ++ "\" for Haskell client/server, picotls client/server, BoringSSL client"
            putStrLn $ "\t\"" ++ configfileO ++ "\" for BoringSSL server"
            putStrLn $ "\t\"" ++ configfileB ++ "\" for DEfO OpenSSL client, NSS client"

            let secfileR = num ++ ".raw"
            BS.writeFile secfileR skm
            let secfileP = num ++ ".pem"
                secPEM =
                    "-----BEGIN PRIVATE KEY-----\n"
                        <> B64.encode (magic <> skm)
                        <> "\n"
                        <> "-----END PRIVATE KEY-----\n"
            BS.writeFile secfileP secPEM
            {-
                        let secfileN = num ++ ".nss"
                            x = magic <> skm -- FIXME: pk is neccessary, sigh.
                            len = BS.length x
                            (a, b) = len `divMod` 256
                            y = BS.pack [fromIntegral a, fromIntegral b] <> x <> encodedConfigList
                            z = B64.encode y
                        BS.writeFile secfileN z
            -}
            let secfileO = hostname ++ num ++ ".pem"
                secconfPEM =
                    secPEM
                        <> "-----BEGIN ECHCONFIG-----\n"
                        <> configB64
                        <> "\n"
                        <> "-----END ECHCONFIG-----\n"
            BS.writeFile secfileO secconfPEM

            putStrLn "ECH server private key files:"
            putStrLn $ "\t\"" ++ secfileR ++ "\" for Haskell server"
            putStrLn $ "\t\"" ++ secfileP ++ "\" for picotls server"

            putStrLn "ECH server private key/config files:"
            putStrLn $ "\t\"" ++ secfileO ++ "\" for DEfO OpenSSL server"
        _ -> putStrLn "ech-gen <public-server-name> <num>"

-- RFC 8410
magic :: ByteString
magic = "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20"
