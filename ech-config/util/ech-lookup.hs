module Main where

import DNS.Do53.Client as DNS
import DNS.SVCB
import DNS.SVCB.Internal
import DNS.Types
import DNS.Types.Opaque
import qualified Data.ByteString as BS
import Network.TLS.ECH.Config
import System.Environment (getArgs)

main :: IO ()
main = do
    [publicName] <- getArgs
    runInitIO $ addResourceDataForSVCB
    let dom = fromRepresentation publicName
    ex <- withLookupConf defaultLookupConf $ \env -> DNS.lookup env dom HTTPS
    case ex of
        Right [r] -> case fromRData r of
            Just https -> case lookupSvcParam SPK_ECH $ https_params https of
                Just (SvcParamValue opq) -> do
                    let ech = toByteString opq
                        fileName = publicName <> ".raw"
                    cnfList <- decodeECHConfigList ech
                    print cnfList
                    BS.writeFile fileName $ toByteString opq
                    putStrLn $ "\"" ++ fileName ++ "\" is created"
                Nothing -> return ()
            Nothing -> return ()
        _ -> return ()
