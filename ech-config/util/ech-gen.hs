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
import qualified Data.ByteString as BS
import Data.Word (Word8)
import Network.TLS.ECH.Config
import System.Environment

configid :: Word8
configid = 1

mkConfig
    :: String
    -> KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> EncodedServerPublicKey
    -> ECHConfig
mkConfig hostname kemid kdfid aeadid pkm =
    ECHConfig
        { contents =
            ECHConfigContents
                { key_config =
                    HpkeKeyConfig
                        { config_id = configid
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
        [hostname] -> do
            let kemid = DHKEM_X25519_HKDF_SHA256
                kdfid = HKDF_SHA256
                aeadid = AES_128_GCM
            (EncodedPublicKey pkm, EncodedSecretKey skm) <-
                genKeyPair defaultHPKEMap kemid
            let config = mkConfig hostname kemid kdfid aeadid (EncodedServerPublicKey pkm)
                configs = [config]
            encodedConfig <- encodeECHConfigList configs
            print configs
            let configfile = hostname ++ ".conf"
            BS.writeFile configfile encodedConfig
            putStrLn $ "\"" ++ configfile ++ "\" is created"
            let secfile = show configid ++ ".key"
            BS.writeFile secfile skm
            putStrLn $ "\"" ++ secfile ++ "\" is created"
        _ -> putStrLn "ech-gen <host>"
