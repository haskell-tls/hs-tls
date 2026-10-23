{-# LANGUAGE FlexibleContexts #-}

module Network.TLS.Record.Decrypt (
    decryptRecord,
    paddingIsValid,
) where

import Control.Monad.State.Strict
import Crypto.Cipher.Types (AuthTag (..))
import Data.ByteArray (convert)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B

import Network.TLS.Cipher
import Network.TLS.Crypto
import Network.TLS.ErrT
import Network.TLS.Imports
import Network.TLS.Packet
import Network.TLS.Record.State
import Network.TLS.Record.Types
import Network.TLS.Struct
import Network.TLS.Util
import Network.TLS.Wire

decryptRecord :: Record Ciphertext -> Int -> RecordM (Record Plaintext)
decryptRecord record@(Record ct ver fragment) lim = do
    st <- get
    case stCipher st of
        Nothing -> noDecryption
        _ -> do
            recOpts <- getRecordOptions
            let mver = recordVersion recOpts
            if recordTLS13 recOpts
                then decryptData13 mver (fragmentGetBytes fragment) st
                else onRecordFragment record $ fragmentUncipher $ \e ->
                    decryptData mver record e st lim
  where
    noDecryption = onRecordFragment record $ fragmentUncipher $ checkPlainLimit lim
    decryptData13 mver e st = case ct of
        ProtocolType_AppData -> do
            inner <- decryptData mver record e st (lim + 1)
            case unInnerPlaintext inner of
                Left message -> throwError $ Error_Protocol message UnexpectedMessage
                Right (ct', d) -> return $ Record ct' ver $ fragmentPlaintext d
        ProtocolType_ChangeCipherSpec -> noDecryption
        -- A peer that fails before it has keys answers in clear, but after
        -- the handshake an alert in clear can only be forged (RFC 8446
        -- Section 5).
        ProtocolType_Alert
            | stCryptLevel st == CryptApplicationSecret ->
                throwError $ Error_Protocol "alert in clear" UnexpectedMessage
            | otherwise -> noDecryption
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

-- | Check a decrypted record.
--
-- The first 'Bool' is what the lengths and the padding already said: 'False'
-- when the padding the record claims cannot be one or is not filled with its
-- length.  It is carried in rather than answered where it was found, so that
-- the MAC is computed either way -- see 'decryptData'.
--
-- Everything is computed before anything is decided, and the verdicts are
-- combined with '&&!', which does not short-circuit.
getCipherData :: Record a -> Bool -> CipherData -> RecordM ByteString
getCipherData (Record pt ver _) lengthValid cdata = do
    -- check if the MAC is valid.
    macValid <- case cipherDataMAC cdata of
        Nothing -> return True
        Just digest -> do
            let new_hdr = Header pt ver (fromIntegral $ B.length $ cipherDataContent cdata)
            expected_digest <- makeDigest new_hdr $ cipherDataContent cdata
            -- constEq rather than (==): (==) on ByteString is memcmp, which
            -- returns as soon as two octets differ, and how soon is a
            -- measurement of how much of the MAC was guessed correctly.
            return (expected_digest `BA.constEq` digest)

    unless (lengthValid &&! macValid) $
        throwError $
            Error_Protocol "bad record mac Stream/Block" BadRecordMac

    return $ cipherDataContent cdata

checkPlainLimit :: Int -> ByteString -> RecordM ByteString
checkPlainLimit lim plain
    | len > lim =
        throwError $
            Error_Protocol
                ( "plaintext exceeding record size limit: "
                    ++ show len
                    ++ " > "
                    ++ show lim
                )
                RecordOverflow
    | otherwise = return plain
  where
    len = B.length plain

decryptData
    :: Version
    -> Record Ciphertext
    -> ByteString
    -> RecordState
    -> Int
    -> RecordM ByteString
decryptData ver record econtent tst lim =
    decryptOf (cstKey cst) >>= checkPlainLimit lim
  where
    cipher = fromJust $ stCipher tst
    bulk = cipherBulk cipher
    cst = stCryptState tst
    macSize = hashDigestSize $ cipherHash cipher
    blockSize = bulkBlockSize bulk
    econtentLen = B.length econtent

    -- A record too short for the cipher cannot be deprotected: RFC 5246
    -- Section 7.2.2 and RFC 8446 Section 5.2 answer it with bad_record_mac.
    sanityCheckError =
        throwError $
            Error_Protocol
                "encrypted content too small for encryption parameters"
                BadRecordMac

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
        modify' $ \txs -> txs{stCryptState = cst{cstIV = iv'}}

        -- The last octet of the plaintext says how much padding there is.
        -- It may say more than the record can hold, and that already settles
        -- the record -- but answering it here, by splitting the record and
        -- failing, would answer it *without computing the MAC*.  How long a
        -- record takes to reject would then say whether the padding length
        -- was plausible, which is the question the attacker is asking.
        --
        -- So carry the verdict instead and go on with a length that fits.
        -- getCipherData folds it in with the MAC, and the answer is the same
        -- BadRecordMac either way.
        let plainlen = B.length content'
            claimed = fromIntegral (B.last content') + 1
            lengthValid = claimed + macSize <= plainlen
            paddinglength = if lengthValid then claimed else 1
            contentlen = plainlen - paddinglength - macSize
            paddingValid = paddingIsValid content' paddinglength
            -- Lucky Thirteen: the rounds a longer padding saves on the MAC.
            dummy = hmacDummyRounds (cipherHash cipher) contentlen (plainlen - 1 - macSize)
        (content, mac, _) <- get3i content' (contentlen, macSize, paddinglength)
        dummy `seq`
            getCipherData
                record
                (lengthValid &&! paddingValid)
                CipherData
                    { cipherDataContent = content
                    , cipherDataMAC = Just mac
                    , cipherDataPadding = Nothing
                    }
    decryptOf (BulkStateStream (BulkStream decryptF)) = do
        -- check if we have enough bytes to cover the minimum for this cipher
        when (econtentLen < macSize) sanityCheckError

        let (content', bulkStream') = decryptF econtent
        {- update Ctx -}
        let contentlen = B.length content' - macSize
        (content, mac) <- get2i content' (contentlen, macSize)
        modify' $ \txs -> txs{stCryptState = cst{cstKey = BulkStateStream bulkStream'}}
        getCipherData
            record
            True
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
                | nonceExpLen == 0 = BA.xor iv sqnc
                | otherwise = iv `B.append` enonce
            (content, authTag2) = decryptF nonce econtent' ad

        when (AuthTag (convert authTag) /= authTag2) $
            throwError $
                Error_Protocol "bad record mac on AEAD" BadRecordMac

        modify' incrRecordState
        return content
    decryptOf BulkStateUninitialized =
        throwError $ Error_Protocol "decrypt state uninitialized" InternalError

    -- the outer format of a record that cannot be deprotected is reported
    -- as an integrity failure too, i.e. BadRecordMac
    get3o s ls =
        maybe (throwError $ Error_Protocol "record bad format" BadRecordMac) return $
            partition3 s ls
    get2o s (d1, d2) = get3o s (d1, d2, 0) >>= \(r1, r2, _) -> return (r1, r2)

    -- all format errors related to decrypted content are reported
    -- externally as integrity failures, i.e. BadRecordMac
    get3i s ls =
        maybe (throwError $ Error_Protocol "record bad format" BadRecordMac) return $
            partition3 s ls
    get2i s (d1, d2) = get3i s (d1, d2, 0) >>= \(r1, r2, _) -> return (r1, r2)

-- | Whether the last @padLen@ octets of the plaintext all equal its last
-- octet.  All 256 octets a padding can span are read, whatever @padLen@.
paddingIsValid :: ByteString -> Int -> Bool
paddingIsValid plain padLen = go 0 0 == 0
  where
    window = B.drop (B.length plain - 256) plain
    wlen = B.length window
    b = B.last plain
    go :: Int -> Word8 -> Word8
    go i acc
        | i == wlen = acc
        | otherwise =
            go (i + 1) $ acc .|. (inPadding i .&. (B.index window (wlen - 1 - i) `xor` b))
    -- 0xff for an octet less than padLen from the end, without a branch
    inPadding i = fromIntegral ((i - padLen) `shiftR` (finiteBitSize i - 1))

-- | HMAC over a shorter content takes fewer compression rounds of the hash.
-- Spend the difference from the longest content on dummy blocks, so that a
-- record takes as long whatever its padding says.
hmacDummyRounds :: Hash -> Int -> Int -> ByteString
hmacDummyRounds h contentLen maxContentLen =
    hash h $ B.take ((rounds maxContentLen - rounds contentLen) * bs) dummyBlocks
  where
    bs = hashBlockSize h
    -- the ipad block, the sequence number and header, the content, and the
    -- 0x80 octet and length field of the hash padding
    rounds n = (bs + 13 + n + 1 + lengthField + bs - 1) `div` bs
    lengthField = if bs == 128 then 16 else 8

dummyBlocks :: ByteString
dummyBlocks = B.replicate (8 * 128) 0
