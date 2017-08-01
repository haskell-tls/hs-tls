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
    , signPrivate
    , decryptRSA
    , verifyPublic
    , generateDHE
    , generateECDHE
    , generateECDHEShared
    , generateFFDHE
    , generateFFDHEShared
    ) where

import qualified Data.ByteString as B

import Network.TLS.Handshake.State
import Network.TLS.State (withRNG, getVersion)
import Network.TLS.Crypto
import Network.TLS.Types
import Network.TLS.Context.Internal
import Network.TLS.Imports

{- if the RSA encryption fails we just return an empty bytestring, and let the protocol
 - fail by itself; however it would be probably better to just report it since it's an internal problem.
 -}
encryptRSA :: Context -> ByteString -> IO ByteString
encryptRSA ctx content = do
    publicKey <- usingHState ctx getRemotePublicKey
    usingState_ ctx $ do
        v <- withRNG $ kxEncrypt publicKey content
        case v of
            Left err       -> fail ("rsa encrypt failed: " ++ show err)
            Right econtent -> return econtent

signPrivate :: Context -> Role -> SignatureParams -> ByteString -> IO ByteString
signPrivate ctx _ params content = do
    privateKey <- usingHState ctx getLocalPrivateKey
    usingState_ ctx $ do
        r <- withRNG $ kxSign privateKey params content
        case r of
            Left err       -> fail ("sign failed: " ++ show err)
            Right econtent -> return econtent

decryptRSA :: Context -> ByteString -> IO (Either KxError ByteString)
decryptRSA ctx econtent = do
    privateKey <- usingHState ctx getLocalPrivateKey
    usingState_ ctx $ do
        ver <- getVersion
        let cipher = if ver < TLS10 then econtent else B.drop 2 econtent
        withRNG $ kxDecrypt privateKey cipher

verifyPublic :: Context -> Role -> SignatureParams -> ByteString -> ByteString -> IO Bool
verifyPublic ctx _ params econtent sign = do
    publicKey <- usingHState ctx getRemotePublicKey
    return $ kxVerify publicKey params econtent sign

generateDHE :: Context -> DHParams -> IO (DHPrivate, DHPublic)
generateDHE ctx dhp = usingState_ ctx $ withRNG $ dhGenerateKeyPair dhp

generateECDHE :: Context -> Group -> IO (GroupPrivate, GroupPublic)
generateECDHE ctx grp = usingState_ ctx $ withRNG $ groupGenerateKeyPair grp

generateECDHEShared :: Context -> GroupPublic -> IO (Maybe (GroupPublic, GroupKey))
generateECDHEShared ctx pub = usingState_ ctx $ withRNG $ groupGetPubShared pub

generateFFDHE :: Context -> Group -> IO (DHParams, DHPrivate, DHPublic)
generateFFDHE ctx grp = usingState_ ctx $ withRNG $ dhGroupGenerateKeyPair grp

generateFFDHEShared :: Context -> Group -> DHPublic -> IO (Maybe (DHPublic, DHKey))
generateFFDHEShared ctx grp pub = usingState_ ctx $ withRNG $ dhGroupGetPubShared grp pub
