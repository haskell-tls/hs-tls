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
    , generateDHE
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Network.TLS.Handshake.State
import Network.TLS.State (withRNG, getVersion)
import Network.TLS.Crypto
import Network.TLS.Types
import Network.TLS.Context.Internal

{- if the RSA encryption fails we just return an empty bytestring, and let the protocol
 - fail by itself; however it would be probably better to just report it since it's an internal problem.
 -}
encryptRSA :: Context -> ByteString -> IO ByteString
encryptRSA ctx content = do
    publicKey <- usingHState ctx getRemotePublicKey
    usingState_ ctx $ do
        v      <- withRNG (\g -> kxEncrypt g publicKey content)
        case v of
            Left err       -> fail ("rsa encrypt failed: " ++ show err)
            Right econtent -> return econtent

signRSA :: Context -> Role -> HashDescr -> ByteString -> IO ByteString
signRSA ctx _ hsh content = do
    privateKey <- usingHState ctx getLocalPrivateKey
    usingState_ ctx $ do
        r      <- withRNG (\g -> kxSign g privateKey hsh content)
        case r of
            Left err       -> fail ("rsa sign failed: " ++ show err)
            Right econtent -> return econtent

decryptRSA :: Context -> ByteString -> IO (Either KxError ByteString)
decryptRSA ctx econtent = do
    privateKey <- usingHState ctx getLocalPrivateKey
    usingState_ ctx $ do
        ver     <- getVersion
        let cipher = if ver < TLS10 then econtent else B.drop 2 econtent
        withRNG (\g -> kxDecrypt g privateKey cipher)

verifyRSA :: Context -> Role -> HashDescr -> ByteString -> ByteString -> IO Bool
verifyRSA ctx _ hsh econtent sign = do
    publicKey <- usingHState ctx getRemotePublicKey
    return $ kxVerify publicKey hsh econtent sign

generateDHE :: Context -> DHParams -> IO (DHPrivate, DHPublic)
generateDHE ctx dhp = usingState_ ctx $ withRNG $ \rng -> dhGenerateKeyPair rng dhp
