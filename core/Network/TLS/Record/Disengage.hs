{-# LANGUAGE FlexibleContexts #-}

module Network.TLS.Record.Disengage (
    disengageRecord,
) where

import Control.Monad.State.Strict
import Crypto.Cipher.Types (AuthTag (..))
import qualified Data.ByteArray as B (convert, xor)
import qualified Data.ByteString as B

import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Crypto
import Network.TLS.ErrT
import Network.TLS.Imports
import Network.TLS.Packet
import Network.TLS.Record.State
import Network.TLS.Record.Types
import Network.TLS.Struct
import Network.TLS.Util
import Network.TLS.Wire

disengageRecord :: Record Ciphertext -> RecordM (Record Plaintext)
disengageRecord = decryptRecord >=> uncompressRecord

uncompressRecord :: Record Compressed -> RecordM (Record Plaintext)
uncompressRecord record = onRecordFragment record $ fragmentUncompress $ \bytes ->
    withCompression $ compressionInflate bytes

decryptRecord :: Record Ciphertext -> RecordM (Record Compressed)
decryptRecord record@(Record ct ver fragment) = do
    st <- get
    case stCipher st of
        Nothing -> noDecryption
        _ -> do
            recOpts <- getRecordOptions
            let mver = recordVersion recOpts
            if recordTLS13 recOpts
                then decryptData13 mver (fragmentGetBytes fragment) st
                else onRecordFragment record $ fragmentUncipher $ \e ->
                    decryptData mver record e st
  where
    noDecryption = onRecordFragment record $ fragmentUncipher return
    decryptData13 mver e st = case ct of
        ProtocolType_AppData -> do
            inner <- decryptData mver record e st
            case unInnerPlaintext inner of
                Left message -> throwError $ Error_Protocol message UnexpectedMessage
                Right (ct', d) -> return $ Record ct' ver (fragmentCompressed d)
        ProtocolType_ChangeCipherSpec -> noDecryption
        ProtocolType_Alert -> noDecryption
        _ ->
            throwError $ Error_Protocol "illegal plain text" UnexpectedMessage

unInnerPlaintext :: ByteString -> Either String (ProtocolType, ByteString)
unInnerPlaintext inner =
    case B.unsnoc dc of
        Nothing -> Left $ unknownContentType13 (0 :: Word8)
        Just (bytes, c)
            | B.null bytes && ProtocolType c `elem` nonEmptyContentTypes ->
                Left ("empty " ++ show (ProtocolType c) ++ " record disallowed")
            | otherwise -> Right (ProtocolType c, bytes)
  where
    (dc, _pad) = B.spanEnd (== 0) inner
    nonEmptyContentTypes = [ProtocolType_Handshake, ProtocolType_Alert]
    unknownContentType13 c = "unknown TLS 1.3 content type: " ++ show c

getCipherData :: Record a -> CipherData -> RecordM ByteString
getCipherData (Record pt ver _) cdata = do
    -- check if the MAC is valid.
    macValid <- case cipherDataMAC cdata of
        Nothing -> return True
        Just digest -> do
            let new_hdr = Header pt ver (fromIntegral $ B.length $ cipherDataContent cdata)
            expected_digest <- makeDigest new_hdr $ cipherDataContent cdata
            return (expected_digest == digest)

    -- check if the padding is filled with the correct pattern if it exists
    -- (before TLS10 this checks instead that the padding length is minimal)
    paddingValid <- case cipherDataPadding cdata of
        Nothing -> return True
        Just (pad, _blksz) -> do
            let b = B.length pad - 1
            return $ B.replicate (B.length pad) (fromIntegral b) == pad

    unless (macValid &&! paddingValid) $
        throwError $
            Error_Protocol "bad record mac" BadRecordMac

    return $ cipherDataContent cdata

decryptData
    :: Version -> Record Ciphertext -> ByteString -> RecordState -> RecordM ByteString
decryptData ver record econtent tst = decryptOf (cstKey cst)
  where
    cipher = fromJust $ stCipher tst
    bulk = cipherBulk cipher
    cst = stCryptState tst
    macSize = hashDigestSize $ cipherHash cipher
    blockSize = bulkBlockSize bulk
    econtentLen = B.length econtent

    sanityCheckError =
        throwError
            (Error_Packet "encrypted content too small for encryption parameters")

    decryptOf :: BulkState -> RecordM ByteString
    decryptOf (BulkStateBlock decryptF) = do
        let minContent = bulkIVSize bulk + max (macSize + 1) blockSize

        -- check if we have enough bytes to cover the minimum for this cipher
        when
            ((econtentLen `mod` blockSize) /= 0 || econtentLen < minContent)
            sanityCheckError

        {- update IV -}
        (iv, econtent') <-
            get2o econtent (bulkIVSize bulk, econtentLen - bulkIVSize bulk)
        let (content', iv') = decryptF iv econtent'
        modify $ \txs -> txs{stCryptState = cst{cstIV = iv'}}

        let paddinglength = fromIntegral (B.last content') + 1
        let contentlen = B.length content' - paddinglength - macSize
        (content, mac, padding) <- get3i content' (contentlen, macSize, paddinglength)
        getCipherData
            record
            CipherData
                { cipherDataContent = content
                , cipherDataMAC = Just mac
                , cipherDataPadding = Just (padding, blockSize)
                }
    decryptOf (BulkStateStream (BulkStream decryptF)) = do
        -- check if we have enough bytes to cover the minimum for this cipher
        when (econtentLen < macSize) sanityCheckError

        let (content', bulkStream') = decryptF econtent
        {- update Ctx -}
        let contentlen = B.length content' - macSize
        (content, mac) <- get2i content' (contentlen, macSize)
        modify $ \txs -> txs{stCryptState = cst{cstKey = BulkStateStream bulkStream'}}
        getCipherData
            record
            CipherData
                { cipherDataContent = content
                , cipherDataMAC = Just mac
                , cipherDataPadding = Nothing
                }
    decryptOf (BulkStateAEAD decryptF) = do
        let authTagLen = bulkAuthTagLen bulk
            nonceExpLen = bulkExplicitIV bulk
            cipherLen = econtentLen - authTagLen - nonceExpLen

        -- check if we have enough bytes to cover the minimum for this cipher
        when (econtentLen < (authTagLen + nonceExpLen)) sanityCheckError

        (enonce, econtent', authTag) <-
            get3o econtent (nonceExpLen, cipherLen, authTagLen)
        let encodedSeq = encodeWord64 $ msSequence $ stMacState tst
            iv = cstIV (stCryptState tst)
            ivlen = B.length iv
            Header typ v _ = recordToHeader record
            hdrLen = if ver >= TLS13 then econtentLen else cipherLen
            hdr = Header typ v $ fromIntegral hdrLen
            ad
                | ver >= TLS13 = encodeHeader hdr
                | otherwise = B.concat [encodedSeq, encodeHeader hdr]
            sqnc = B.replicate (ivlen - 8) 0 `B.append` encodedSeq
            nonce
                | nonceExpLen == 0 = B.xor iv sqnc
                | otherwise = iv `B.append` enonce
            (content, authTag2) = decryptF nonce econtent' ad

        when (AuthTag (B.convert authTag) /= authTag2) $
            throwError $
                Error_Protocol "bad record mac" BadRecordMac

        modify incrRecordState
        return content
    decryptOf BulkStateUninitialized =
        throwError $ Error_Protocol "decrypt state uninitialized" InternalError

    -- handling of outer format can report errors with Error_Packet
    get3o s ls =
        maybe (throwError $ Error_Packet "record bad format") return $ partition3 s ls
    get2o s (d1, d2) = get3o s (d1, d2, 0) >>= \(r1, r2, _) -> return (r1, r2)

    -- all format errors related to decrypted content are reported
    -- externally as integrity failures, i.e. BadRecordMac
    get3i s ls =
        maybe (throwError $ Error_Protocol "record bad format" BadRecordMac) return $
            partition3 s ls
    get2i s (d1, d2) = get3i s (d1, d2, 0) >>= \(r1, r2, _) -> return (r1, r2)
