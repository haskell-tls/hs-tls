{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module ECHSpec (spec) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Lazy as L
import Data.Maybe
import Network.TLS
import Network.TLS.ECH.Config
import Network.TLS.Extra.Cipher
import Network.TLS.Internal
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

import Arbitrary
import Run
import Session

spec :: Spec
spec = do
    describe "ECH" $ do
        prop "can handshake with TLS 1.3 Full" handshake13_full
        prop "can handshake with TLS 1.3 HRR" handshake13_hrr
        prop "can handshake with TLS 1.3 PSK" handshake13_psk
        prop "can handshake with TLS 1.3 PSK ticket" handshake13_psk_ticket
        prop "can handshake with TLS 1.3 PSK -> HRR" handshake13_psk_fallback
        prop "can handshake with TLS 1.3 0RTT" handshake13_0rtt
        prop "can handshake with TLS 1.3 0RTT -> PSK" handshake13_0rtt_fallback
        prop "can handshake with TLS 1.3 EC groups" handshake13_ec
        prop "can handshake with TLS 1.3 FFDHE groups" handshake13_ffdhe
    describe "ECH greasing" $ do
        prop "sends greasing ECH" handshake13_greasing

--------------------------------------------------------------

newtype CSP13 = CSP13 (ClientParams, ServerParams) deriving (Show)

instance Arbitrary CSP13 where
    arbitrary = CSP13 <$> arbitraryPairParams13

--------------------------------------------------------------

handshake13_full :: CSP13 -> IO ()
handshake13_full (CSP13 (cli, srv)) = do
    let cliSupported =
            defaultSupported
                { supportedCiphers = [cipher13_AES_128_GCM_SHA256]
                , supportedGroups = [X25519]
                }
        svrSupported =
            defaultSupported
                { supportedCiphers = [cipher13_AES_128_GCM_SHA256]
                , supportedGroups = [X25519]
                }
        params =
            setParams
                ( cli{clientSupported = cliSupported}
                , srv{serverSupported = svrSupported}
                )
    runTLSSimple13ECH params FullHandshake

handshake13_hrr :: CSP13 -> IO ()
handshake13_hrr (CSP13 (cli, srv)) = do
    let cliSupported =
            defaultSupported
                { supportedCiphers = [cipher13_AES_128_GCM_SHA256]
                , supportedGroups = [P256, X25519]
                }
        svrSupported =
            defaultSupported
                { supportedCiphers = [cipher13_AES_128_GCM_SHA256]
                , supportedGroups = [X25519]
                }
        params =
            setParams
                ( cli{clientSupported = cliSupported}
                , srv{serverSupported = svrSupported}
                )
    runTLSSimple13ECH params HelloRetryRequest

handshake13_psk :: CSP13 -> IO ()
handshake13_psk (CSP13 (cli, srv)) = do
    let cliSupported =
            defaultSupported
                { supportedCiphers = [cipher13_AES_128_GCM_SHA256]
                , supportedGroups = [P256, X25519]
                }
        svrSupported =
            defaultSupported
                { supportedCiphers = [cipher13_AES_128_GCM_SHA256]
                , supportedGroups = [X25519]
                }
        params0 =
            setParams
                ( cli{clientSupported = cliSupported}
                , srv{serverSupported = svrSupported}
                )

    sessionRefs <- twoSessionRefs
    let sessionManagers = twoSessionManagers sessionRefs

    let params = setPairParamsSessionManagers sessionManagers params0

    runTLSSimple13ECH params HelloRetryRequest

    -- and resume
    sessionParams <- readClientSessionRef sessionRefs
    expectJust "session param should be Just" sessionParams
    let params2 = setPairParamsSessionResuming (fromJust sessionParams) params

    runTLSSimple13ECH params2 PreSharedKey

handshake13_psk_ticket :: CSP13 -> IO ()
handshake13_psk_ticket (CSP13 (cli, srv)) = do
    let cliSupported =
            defaultSupported
                { supportedCiphers = [cipher13_AES_128_GCM_SHA256]
                , supportedGroups = [P256, X25519]
                }
        svrSupported =
            defaultSupported
                { supportedCiphers = [cipher13_AES_128_GCM_SHA256]
                , supportedGroups = [X25519]
                }
        params0 =
            setParams
                ( cli{clientSupported = cliSupported}
                , srv{serverSupported = svrSupported}
                )

    sessionRefs <- twoSessionRefs
    let sessionManagers0 = twoSessionManagers sessionRefs
        sessionManagers = (fst sessionManagers0, oneSessionTicket)

    let params = setPairParamsSessionManagers sessionManagers params0

    runTLSSimple13ECH params HelloRetryRequest

    -- and resume
    sessionParams <- readClientSessionRef sessionRefs
    expectJust "session param should be Just" sessionParams
    let params2 = setPairParamsSessionResuming (fromJust sessionParams) params

    runTLSSimple13ECH params2 PreSharedKey

handshake13_psk_fallback :: CSP13 -> IO ()
handshake13_psk_fallback (CSP13 (cli, srv)) = do
    let cliSupported =
            defaultSupported
                { supportedCiphers =
                    [ cipher13_AES_128_GCM_SHA256
                    , cipher13_AES_128_CCM_SHA256
                    ]
                , supportedGroups = [P256, X25519]
                }
        svrSupported =
            defaultSupported
                { supportedCiphers = [cipher13_AES_128_GCM_SHA256]
                , supportedGroups = [X25519]
                }
        params0 =
            setParams
                ( cli{clientSupported = cliSupported}
                , srv{serverSupported = svrSupported}
                )

    sessionRefs <- twoSessionRefs
    let sessionManagers = twoSessionManagers sessionRefs

    let params = setPairParamsSessionManagers sessionManagers params0

    runTLSSimple13ECH params HelloRetryRequest

    -- resumption fails because GCM cipher is not supported anymore, full
    -- handshake is not possible because X25519 has been removed, so we are
    -- back with P256 after hello retry
    sessionParams <- readClientSessionRef sessionRefs
    expectJust "session param should be Just" sessionParams
    let (cli2, srv2) = setPairParamsSessionResuming (fromJust sessionParams) params
        srv2' = srv2{serverSupported = svrSupported'}
        svrSupported' =
            defaultSupported
                { supportedCiphers = [cipher13_AES_128_CCM_SHA256]
                , supportedGroups = [P256]
                }

    runTLSSimple13ECH (cli2, srv2') HelloRetryRequest

handshake13_0rtt :: CSP13 -> IO ()
handshake13_0rtt (CSP13 (cli, srv)) = do
    let cliSupported =
            defaultSupported
                { supportedCiphers = [cipher13_AES_128_GCM_SHA256]
                , supportedGroups = [P256, X25519]
                }
        svrSupported =
            defaultSupported
                { supportedCiphers = [cipher13_AES_128_GCM_SHA256]
                , supportedGroups = [X25519]
                }
        cliHooks =
            defaultClientHooks
                { onSuggestALPN = return $ Just ["h2"]
                }
        svrHooks =
            defaultServerHooks
                { onALPNClientSuggest = Just (return . unsafeHead)
                }
        params0 =
            setParams
                ( cli
                    { clientSupported = cliSupported
                    , clientHooks = cliHooks
                    }
                , srv
                    { serverSupported = svrSupported
                    , serverHooks = svrHooks
                    , serverEarlyDataSize = 2048
                    }
                )

    sessionRefs <- twoSessionRefs
    let sessionManagers = twoSessionManagers sessionRefs

    let params = setPairParamsSessionManagers sessionManagers params0

    runTLSSimple13ECH params HelloRetryRequest
    runTLS0rtt params sessionRefs
    runTLS0rtt params sessionRefs
  where
    runTLS0rtt params sessionRefs = do
        -- and resume
        sessionParams <- readClientSessionRef sessionRefs
        expectJust "session param should be Just" sessionParams
        clearClientSessionRef sessionRefs
        earlyData <- B.pack <$> generate (someWords8 256)
        let (pc, ps) = setPairParamsSessionResuming (fromJust sessionParams) params
            params2 = (pc{clientUseEarlyData = True}, ps)

        runTLS0RTTech params2 RTT0 earlyData

handshake13_0rtt_fallback :: CSP13 -> IO ()
handshake13_0rtt_fallback (CSP13 (cli, srv)) = do
    group0 <- generate $ elements [P256, X25519]
    let cliSupported =
            defaultSupported
                { supportedCiphers = [cipher13_AES_128_GCM_SHA256]
                , supportedGroups = [P256, X25519]
                }
        svrSupported =
            defaultSupported
                { supportedCiphers = [cipher13_AES_128_GCM_SHA256]
                , supportedGroups = [group0]
                }
        params =
            setParams
                ( cli{clientSupported = cliSupported}
                , srv
                    { serverSupported = svrSupported
                    , serverEarlyDataSize = 1024
                    }
                )

    sessionRefs <- twoSessionRefs
    let sessionManagers = twoSessionManagers sessionRefs

    let params0 = setPairParamsSessionManagers sessionManagers params

    let mode = if group0 == P256 then FullHandshake else HelloRetryRequest
    runTLSSimple13ECH params0 mode

    -- and resume
    mSessionParams <- readClientSessionRef sessionRefs
    case mSessionParams of
        Nothing -> expectationFailure "session params: Just is expected"
        Just sessionParams -> do
            earlyData <- B.pack <$> generate (someWords8 256)
            group1 <- generate $ elements [P256, X25519]
            let (pc, ps) = setPairParamsSessionResuming sessionParams params0
                svrSupported1 =
                    defaultSupported
                        { supportedCiphers = [cipher13_AES_128_GCM_SHA256]
                        , supportedGroups = [group1]
                        }
                params1 =
                    ( pc{clientUseEarlyData = True}
                    , ps
                        { serverEarlyDataSize = 0
                        , serverSupported = svrSupported1
                        }
                    )
            -- C: [P256, X25519]
            -- S: [group0]
            -- C: [P256, X25519]
            -- S: [group1]
            if group0 == group1
                -- 0-RTT is not allowed, so fallback to PreSharedKey
                then runTLS0RTTech params1 PreSharedKey earlyData
                -- HRR but not allowed for 0-RTT
                else runTLSFailure params1 (tlsClient earlyData) tlsServer
  where
    tlsClient earlyData ctx = do
        handshake ctx
        sendData ctx $ L.fromStrict earlyData
        _ <- recvData ctx
        bye ctx
    tlsServer ctx = do
        handshake ctx
        _ <- recvData ctx
        bye ctx

handshake13_ec :: CSP13 -> IO ()
handshake13_ec (CSP13 (cli, srv)) = do
    EC cgrps <- generate arbitrary
    EC sgrps <- generate arbitrary
    let cliSupported = (clientSupported cli){supportedGroups = cgrps}
        svrSupported = (serverSupported srv){supportedGroups = sgrps}
        params =
            setParams
                ( cli{clientSupported = cliSupported}
                , srv{serverSupported = svrSupported}
                )
    runTLSSimple13ECH params FullHandshake

handshake13_ffdhe :: CSP13 -> IO ()
handshake13_ffdhe (CSP13 (cli, srv)) = do
    FFDHE cgrps <- generate arbitrary
    FFDHE sgrps <- generate arbitrary
    let cliSupported = (clientSupported cli){supportedGroups = cgrps}
        svrSupported = (serverSupported srv){supportedGroups = sgrps}
        params =
            setParams
                ( cli{clientSupported = cliSupported}
                , srv{serverSupported = svrSupported}
                )
    runTLSSimple13ECH params FullHandshake

handshake13_greasing :: CSP13 -> IO ()
handshake13_greasing (CSP13 (cli, srv)) = do
    let cliSupported =
            defaultSupported
                { supportedCiphers = [cipher13_AES_128_GCM_SHA256]
                , supportedGroups = [X25519]
                }
        svrSupported =
            defaultSupported
                { supportedCiphers = [cipher13_AES_128_GCM_SHA256]
                , supportedGroups = [X25519]
                }
        params =
            ( cli
                { clientSupported = cliSupported
                , clientUseECH = True
                , clientShared = (clientShared cli){sharedECHConfig = echConfList}
                }
            , srv{serverSupported = svrSupported}
            )
    (clientMessages, _) <- runTLSCaptureFail params
    let isGreasing (ExtensionRaw eid _) = eid == EID_EncryptedClientHello
        eeMessagesHaveExt =
            [ any isGreasing chExtensions
            | ClientHello CH{..} <- clientMessages
            ]
    eeMessagesHaveExt `shouldBe` [True]

expectJust :: String -> Maybe a -> Expectation
expectJust tag mx = case mx of
    Nothing -> expectationFailure tag
    Just _ -> return ()

setParams :: (ClientParams, ServerParams) -> (ClientParams, ServerParams)
setParams (cli, srv) = (cli', srv')
  where
    cli' =
        cli
            { clientUseECH = True
            , clientShared = (clientShared cli){sharedECHConfig = echConfList}
            }
    srv' =
        srv
            { serverECHKey = echKey
            , serverShared = (serverShared srv){sharedECHConfig = echConfList}
            }

echKey :: [(ConfigId, ByteString)]
echKey = [(0, B64.decodeLenient "GAl/YqzDDnssODe5t+2xlQsbSv26kNlfJ0D+nZbK62I=")]

echConfList :: ECHConfigList
echConfList =
    fromJust $
        decodeECHConfigList $
            B64.decodeLenient
                "AEP+DQA/AAAgACDGNVZWrmqQfzAuYGJNa8+OEc6zaUfzd0ltyJQ2y1U2AwAEAAEAAQAQcHVibGljLWxvY2FsaG9zdAAA"
