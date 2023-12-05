module HandshakeSpec where

import qualified Data.ByteString as B
import Network.TLS
import Test.Hspec
import Test.QuickCheck

import Arbitrary
import PipeChan
import Run

spec :: Spec
spec = do
    describe "pipe" $ do
        it "can setup a channel" $ pipe_work
    describe "handshake" $ do
        it "can run TLS 1.2" $ do
            params <- generate arbitraryPairParams
            runTLSPipeSimple params

        it "can run TLS 1.3" $ do
            params <- generate arbitraryPairParams13
            let cgrps = supportedGroups $ clientSupported $ fst params
                sgrps = supportedGroups $ serverSupported $ snd params
                hs = if head cgrps `elem` sgrps then FullHandshake else HelloRetryRequest
            runTLSPipeSimple13 params hs Nothing

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
