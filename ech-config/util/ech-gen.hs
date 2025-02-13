{-# LANGUAGE OverloadedStrings #-}

module Main where

import Crypto.HPKE (AEAD_ID (..), KDF_ID (..), KEM_ID (..))
import qualified Crypto.HPKE as HPKE
import qualified Crypto.HPKE.Internal as HPKE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Network.ByteOrder
import Network.TLS.ECH.Config
import System.Environment

mkConfig
    :: ByteString
    -> KEM_ID
    -> KDF_ID
    -> AEAD_ID
    -> EncodedPublicKey
    -> ECHConfig
mkConfig hostname kemid kdfid aeadid pkm =
    ECHConfig
        { contents =
            ECHConfigContents
                { key_config =
                    HpkeKeyConfig
                        { config_id = 1
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
        [hostname, pubfile, secfile] -> do
            let kemid = DHKEM_X25519_HKDF_SHA256
                kdfid = HKDF_SHA256
                aeadid = AES_128_GCM
            (HPKE.EncodedPublicKey pkm, HPKE.EncodedSecretKey skm) <-
                HPKE.genKeyPair HPKE.defaultHPKEMap kemid
            let config = mkConfig (C8.pack hostname) kemid kdfid aeadid (EncodedPublicKey pkm)
                configs = [config]
                siz = sum $ map sizeOfECHConfig configs
            encodedConfig <- withWriteBuffer (siz + 2) $ \wbuf -> do
                write16 wbuf $ fromIntegral siz
                mapM_ (putECHConfig wbuf) configs
            print configs
            BS.writeFile pubfile encodedConfig
            BS.writeFile secfile skm
        _ -> putStrLn "ech-gen <host> <pub_file> <sec_file>"
