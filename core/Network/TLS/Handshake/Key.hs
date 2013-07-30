-- |
-- Module      : Network.TLS.Handshake.Key
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- functions for RSA operations
--
module Network.TLS.Handshake.Key
    ( encryptRSA
    , signRSA
    , decryptRSA
    , verifyRSA
    ) where

import Control.Applicative ((<$>))
import Control.Monad.State

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Network.TLS.Util
import Network.TLS.State
import Network.TLS.Crypto
import Network.TLS.Types

{- if the RSA encryption fails we just return an empty bytestring, and let the protocol
 - fail by itself; however it would be probably better to just report it since it's an internal problem.
 -}
encryptRSA :: ByteString -> TLSSt ByteString
encryptRSA content = do
    rsakey <- fromJust "rsa public key" . hstRSAPublicKey . fromJust "handshake" . stHandshake <$> get
    v      <- withRNG (\g -> kxEncrypt g rsakey content)
    case v of
        Left err       -> fail ("rsa encrypt failed: " ++ show err)
        Right econtent -> return econtent

signRSA :: HashDescr -> ByteString -> TLSSt ByteString
signRSA hsh content = do
    rsakey <- fromJust "rsa client private key" . hstRSAClientPrivateKey . fromJust "handshake" . stHandshake <$> get
    r      <- withRNG (\g -> kxSign g rsakey hsh content)
    case r of
        Left err       -> fail ("rsa sign failed: " ++ show err)
        Right econtent -> return econtent

decryptRSA :: ByteString -> TLSSt (Either KxError ByteString)
decryptRSA econtent = do
    ver     <- getVersion
    rsapriv <- fromJust "rsa private key" . hstRSAPrivateKey . fromJust "handshake" . stHandshake <$> get
    let cipher = if ver < TLS10 then econtent else B.drop 2 econtent
    withRNG (\g -> kxDecrypt g rsapriv cipher)

verifyRSA :: HashDescr -> ByteString -> ByteString -> TLSSt Bool
verifyRSA hsh econtent sign = do
    rsapriv <- fromJust "rsa client public key" . hstRSAClientPublicKey . fromJust "handshake" . stHandshake <$> get
    return $ kxVerify rsapriv hsh econtent sign

