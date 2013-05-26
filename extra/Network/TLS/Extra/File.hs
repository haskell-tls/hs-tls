-- |
-- Module      : Network.TLS.Extra.File
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Simple helpers to load private key and certificate files
-- to be handled by the TLS stack
module Network.TLS.Extra.File 
    ( fileReadCertificate
    , fileReadPrivateKey
    ) where

import Control.Applicative ((<$>))
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Either
import Data.PEM (PEM(..), pemParseBS)
import Data.Certificate.X509
import qualified Data.Certificate.KeyRSA as KeyRSA
import Network.TLS

-- | read one X509 certificate from a file.
--
-- the certificate must be in the usual PEM format with the
-- TRUSTED CERTIFICATE or CERTIFICATE pem name.
--
-- If no valid PEM encoded certificate is found in the file
-- this function will raise an error.
fileReadCertificate :: FilePath -> IO SignedCertificate
fileReadCertificate filepath = do
    certs <- rights . parseCerts . pemParseBS <$> B.readFile filepath
    case certs of
        []    -> error "no valid certificate found"
        (x:_) -> return x
    where parseCerts (Right pems) = map (decodeCertificate . L.fromChunks . (:[]) . pemContent)
                                  $ filter (flip elem ["CERTIFICATE", "TRUSTED CERTIFICATE"] . pemName) pems
          parseCerts (Left err) = error ("cannot parse PEM file " ++ show err)

-- | read one private key from a file.
--
-- the private key must be in the usual PEM format and at the moment only
-- RSA PRIVATE KEY are supported.
--
-- If no valid PEM encoded private key is found in the file
-- this function will raise an error.
fileReadPrivateKey :: FilePath -> IO PrivateKey
fileReadPrivateKey filepath = do
    pk <- rights . parseKey . pemParseBS <$> B.readFile filepath
    case pk of
        []    -> error "no valid RSA key found"
        (x:_) -> return x

    where parseKey (Right pems) = map (fmap (PrivRSA . snd) . KeyRSA.decodePrivate . L.fromChunks . (:[]) . pemContent)
                                $ filter ((== "RSA PRIVATE KEY") . pemName) pems
          parseKey (Left err) = error ("Cannot parse PEM file " ++ show err)
