{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.State13 (
    CryptLevel (
        CryptEarlySecret,
        CryptHandshakeSecret,
        CryptApplicationSecret
    ),
    TrafficSecret,
    getTxRecordState,
    getRxRecordState,
    setTxRecordState,
    setRxRecordState,
    getTxLevel,
    getRxLevel,
    clearTxRecordState,
    clearRxRecordState,
    PendingRecvAction (..),
    setPendingRecvActions,
    popPendingRecvAction,
) where

import Control.Concurrent.MVar
import Data.IORef

import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Context.Internal
import Network.TLS.Imports
import Network.TLS.KeySchedule (hkdfExpandLabel)
import Network.TLS.Record.State
import Network.TLS.Types

getTxRecordState :: Context -> IO (Hash, Cipher, CryptLevel, ByteString)
getTxRecordState ctx = getXState ctx ctxTxRecordState

getRxRecordState :: Context -> IO (Hash, Cipher, CryptLevel, ByteString)
getRxRecordState ctx = getXState ctx ctxRxRecordState

getXState
    :: Context
    -> (Context -> MVar RecordState)
    -> IO (Hash, Cipher, CryptLevel, ByteString)
getXState ctx func = do
    tx <- readMVar (func ctx)
    let usedCipher = fromJust $ stCipher tx
        usedHash = cipherHash usedCipher
        level = stCryptLevel tx
        secret = cstMacSecret $ stCryptState tx
    return (usedHash, usedCipher, level, secret)

-- In the case of QUIC, stCipher is Nothing.
-- So, fromJust causes an error.
getTxLevel :: Context -> IO CryptLevel
getTxLevel ctx = getXLevel ctx ctxTxRecordState

getRxLevel :: Context -> IO CryptLevel
getRxLevel ctx = getXLevel ctx ctxRxRecordState

getXLevel
    :: Context
    -> (Context -> MVar RecordState)
    -> IO CryptLevel
getXLevel ctx func = do
    tx <- readMVar (func ctx)
    return $ stCryptLevel tx

class TrafficSecret ty where
    fromTrafficSecret :: ty -> (CryptLevel, ByteString)

instance HasCryptLevel a => TrafficSecret (AnyTrafficSecret a) where
    fromTrafficSecret prx@(AnyTrafficSecret s) = (getCryptLevel prx, s)

instance HasCryptLevel a => TrafficSecret (ClientTrafficSecret a) where
    fromTrafficSecret prx@(ClientTrafficSecret s) = (getCryptLevel prx, s)

instance HasCryptLevel a => TrafficSecret (ServerTrafficSecret a) where
    fromTrafficSecret prx@(ServerTrafficSecret s) = (getCryptLevel prx, s)

setTxRecordState :: TrafficSecret ty => Context -> Hash -> Cipher -> ty -> IO ()
setTxRecordState = setXState ctxTxRecordState BulkEncrypt

setRxRecordState :: TrafficSecret ty => Context -> Hash -> Cipher -> ty -> IO ()
setRxRecordState = setXState ctxRxRecordState BulkDecrypt

setXState
    :: TrafficSecret ty
    => (Context -> MVar RecordState)
    -> BulkDirection
    -> Context
    -> Hash
    -> Cipher
    -> ty
    -> IO ()
setXState func encOrDec ctx h cipher ts =
    let (lvl, secret) = fromTrafficSecret ts
     in setXState' func encOrDec ctx h cipher lvl secret

setXState'
    :: (Context -> MVar RecordState)
    -> BulkDirection
    -> Context
    -> Hash
    -> Cipher
    -> CryptLevel
    -> ByteString
    -> IO ()
setXState' func encOrDec ctx h cipher lvl secret =
    modifyMVar_ (func ctx) (\_ -> return rt)
  where
    bulk = cipherBulk cipher
    keySize = bulkKeySize bulk
    ivSize = max 8 (bulkIVSize bulk + bulkExplicitIV bulk)
    key = hkdfExpandLabel h secret "key" "" keySize
    iv = hkdfExpandLabel h secret "iv" "" ivSize
    cst =
        CryptState
            { cstKey = bulkInit bulk encOrDec key
            , cstIV = iv
            , cstMacSecret = secret
            }
    rt =
        RecordState
            { stCryptState = cst
            , stMacState = MacState{msSequence = 0}
            , stCryptLevel = lvl
            , stCipher = Just cipher
            , stCompression = nullCompression
            }

clearTxRecordState :: Context -> IO ()
clearTxRecordState = clearXState ctxTxRecordState

clearRxRecordState :: Context -> IO ()
clearRxRecordState = clearXState ctxRxRecordState

clearXState :: (Context -> MVar RecordState) -> Context -> IO ()
clearXState func ctx =
    modifyMVar_ (func ctx) (\rt -> return rt{stCipher = Nothing})

setPendingRecvActions :: Context -> [PendingRecvAction] -> IO ()
setPendingRecvActions ctx = writeIORef (ctxPendingRecvActions ctx)

popPendingRecvAction :: Context -> IO (Maybe PendingRecvAction)
popPendingRecvAction ctx = do
    let ref = ctxPendingRecvActions ctx
    actions <- readIORef ref
    case actions of
        bs : bss -> writeIORef ref bss >> return (Just bs)
        [] -> return Nothing
