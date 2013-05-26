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
import Data.X509.File
import Data.X509

-- | read one X509 certificate from a file.
--
-- the certificate must be in the usual PEM format with the
-- TRUSTED CERTIFICATE or CERTIFICATE pem name.
--
-- If no valid PEM encoded certificate is found in the file
-- this function will raise an error.
fileReadCertificate :: FilePath -> IO SignedCertificate
fileReadCertificate filepath = headError <$> readSignedObject filepath
  where headError []    = error ("read certificate: not found in " ++ show filepath)
        headError (x:_) = x
{-
                                  $ filter (flip elem ["CERTIFICATE", "TRUSTED CERTIFICATE"] . pemName) pems
-}

-- | read one private key from a file.
--
-- the private key must be in the usual PEM format
--
-- If no valid PEM encoded private key is found in the file
-- this function will raise an error.
fileReadPrivateKey :: FilePath -> IO PrivKey
fileReadPrivateKey filepath = headError <$> readKeyFile filepath
  where headError []    = error ("read private key: no key found in " ++ show filepath)
        headError (x:_) = x
