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
    , fileReadCertificateChain
    , fileReadPrivateKey
    ) where

import Control.Applicative ((<$>))
import Data.X509.File
import Data.X509

-- | read one X509 certificate from a file.
--
-- the certificate must be in the usual PEM format
--
-- If no valid PEM encoded certificate is found in the file
-- this function will raise an error.
fileReadCertificate :: FilePath -> IO SignedCertificate
fileReadCertificate filepath = headError <$> readSignedObject filepath
  where headError []    = error ("read certificate: not found in " ++ show filepath)
        headError (x:_) = x

-- | read a CertificateChain from a file.
--
-- No checks are performed on the chain itself for validity or consistency.
--
-- the expected format is the list of PEM encoded signed certificate,
-- with the first one being the subject of the chain.
--
fileReadCertificateChain :: FilePath -> IO CertificateChain
fileReadCertificateChain filepath = CertificateChain <$> readSignedObject filepath

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
