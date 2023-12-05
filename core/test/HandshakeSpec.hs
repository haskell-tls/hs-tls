module HandshakeSpec where

import qualified Data.ByteString as B
import Data.List
import Data.Maybe
import Network.TLS
import Network.TLS.Extra.Cipher
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

import Arbitrary
import PipeChan
import Run

spec :: Spec
spec = do
    describe "pipe" $ do
        it "can setup a channel" pipe_work
    describe "handshake" $ do
        prop "can run TLS 1.2" handshake_simple
        prop "can run TLS 1.3" handshake13_simple
        prop "can update key for TLS 1.3" handshake_update_key
        prop "can prevent downgrade attack" handshake13_downgrade
        prop "can negotiate hash and signature" handshake_hashsignatures
        prop "can negotiate cipher suite" handshake_ciphersuites
        prop "can negotiate group" handshake_groups

pipe_work :: IO ()
pipe_work = do
    pipe <- newPipe
    _ <- runPipe pipe

    let bSize = 16
    n <- generate (choose (1, 32))

    let d1 = B.replicate (bSize * n) 40
    let d2 = B.replicate (bSize * n) 45

    d1' <- writePipeA pipe d1 >> readPipeB pipe (B.length d1)
    d1 `shouldBe` d1'

    d2' <- writePipeB pipe d2 >> readPipeA pipe (B.length d2)
    d2 `shouldBe` d2'

handshake_simple :: CSP -> IO ()
handshake_simple (CSP params) = runTLSPipeSimple params

handshake13_simple :: CSP13 -> IO ()
handshake13_simple (CSP13 params) = runTLSPipeSimple13 params hs Nothing
  where
    cgrps = supportedGroups $ clientSupported $ fst params
    sgrps = supportedGroups $ serverSupported $ snd params
    hs = if head cgrps `elem` sgrps then FullHandshake else HelloRetryRequest

handshake13_downgrade :: CSP -> IO ()
handshake13_downgrade (CSP (cparam,sparam)) = do
    versionForced <- generate $ elements (supportedVersions $ clientSupported cparam)
    let debug' = (serverDebug sparam){debugVersionForced = Just versionForced}
        sparam' = sparam{serverDebug = debug'}
        params = (cparam, sparam')
        downgraded =
            (isVersionEnabled TLS13 params && versionForced < TLS13)
                || (isVersionEnabled TLS12 params && versionForced < TLS12)
    if downgraded
        then runTLSInitFailure params
        else runTLSPipeSimple params

handshake_update_key :: CSP -> IO ()
handshake_update_key (CSP params) = runTLSPipeSimpleKeyUpdate params

handshake_hashsignatures :: Bool -> IO ()
handshake_hashsignatures tls13 = do
    let version = if tls13 then TLS13 else TLS12
        ciphers =
            [ cipher_ECDHE_RSA_AES256GCM_SHA384
            , cipher_ECDHE_ECDSA_AES256GCM_SHA384
            , cipher_ECDHE_RSA_AES128CBC_SHA
            , cipher_ECDHE_ECDSA_AES128CBC_SHA
            , cipher_DHE_RSA_AES128_SHA1
            , cipher_TLS13_AES128GCM_SHA256
            ]
    (clientParam, serverParam) <-
        generate $
            arbitraryPairParamsWithVersionsAndCiphers
                ([version], [version])
                (ciphers, ciphers)
    clientHashSigs <- generate $ arbitraryHashSignatures version
    serverHashSigs <- generate $ arbitraryHashSignatures version
    let clientParam' =
            clientParam
                { clientSupported =
                    (clientSupported clientParam)
                        { supportedHashSignatures = clientHashSigs
                        }
                }
        serverParam' =
            serverParam
                { serverSupported =
                    (serverSupported serverParam)
                        { supportedHashSignatures = serverHashSigs
                        }
                }
        commonHashSigs = clientHashSigs `intersect` serverHashSigs
        shouldFail
            | tls13 = all incompatibleWithDefaultCurve commonHashSigs
            | otherwise = null commonHashSigs
    if shouldFail
        then runTLSInitFailure (clientParam', serverParam')
        else runTLSPipeSimple (clientParam', serverParam')
  where
    incompatibleWithDefaultCurve (h, SignatureECDSA) = h /= HashSHA256
    incompatibleWithDefaultCurve _ = False

handshake_ciphersuites :: ([Cipher], [Cipher]) -> IO ()
handshake_ciphersuites (clientCiphers, serverCiphers) = do
    tls13 <- generate arbitrary
    let version = if tls13 then TLS13 else TLS12
    (clientParam, serverParam) <-
        generate $
            arbitraryPairParamsWithVersionsAndCiphers
                ([version], [version])
                (clientCiphers, serverCiphers)
    let adequate = cipherAllowedForVersion version
        shouldSucceed = any adequate (clientCiphers `intersect` serverCiphers)
    if shouldSucceed
        then runTLSPipeSimple (clientParam, serverParam)
        else runTLSInitFailure (clientParam, serverParam)

handshake_groups :: ([Group], [Group]) -> IO ()
handshake_groups (clientGroups, serverGroups) = do
    tls13 <- generate arbitrary
    let versions = if tls13 then [TLS13] else [TLS12]
        ciphers =
            [ cipher_ECDHE_RSA_AES256GCM_SHA384
            , cipher_ECDHE_RSA_AES128CBC_SHA
            , cipher_DHE_RSA_AES256GCM_SHA384
            , cipher_DHE_RSA_AES128_SHA1
            , cipher_TLS13_AES128GCM_SHA256
            ]
    (clientParam, serverParam) <-
        generate $
            arbitraryPairParamsWithVersionsAndCiphers
                (versions, versions)
                (ciphers, ciphers)
    denyCustom <- generate arbitrary
    let groupUsage =
            if denyCustom
                then GroupUsageUnsupported "custom group denied"
                else GroupUsageValid
        clientParam' =
            clientParam
                { clientSupported =
                    (clientSupported clientParam)
                        { supportedGroups = clientGroups
                        }
                , clientHooks =
                    (clientHooks clientParam)
                        { onCustomFFDHEGroup = \_ _ -> return groupUsage
                        }
                }
        serverParam' =
            serverParam
                { serverSupported =
                    (serverSupported serverParam)
                        { supportedGroups = serverGroups
                        }
                }
        isCustom = maybe True isCustomDHParams (serverDHEParams serverParam')
        mCustomGroup = serverDHEParams serverParam' >>= dhParamsGroup
        isClientCustom = maybe True (`notElem` clientGroups) mCustomGroup
        commonGroups = clientGroups `intersect` serverGroups
        shouldFail = null commonGroups && (tls13 || isClientCustom && denyCustom)
        p minfo = isNothing (minfo >>= infoSupportedGroup) == (null commonGroups && isCustom)
    if shouldFail
        then runTLSInitFailure (clientParam', serverParam')
        else runTLSPipePredicate (clientParam', serverParam') p
