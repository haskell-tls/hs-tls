{-# LANGUAGE ExistentialQuantification #-}
{-# OPTIONS_HADDOCK hide #-}

module Network.TLS.Cipher (
    CipherKeyExchangeType (..),
    Bulk (..),
    BulkFunctions (..),
    BulkDirection (..),
    BulkState (..),
    BulkStream (..),
    BulkBlock,
    BulkAEAD,
    bulkInit,
    Hash (..),
    Cipher (..),
    CipherID,
    cipherKeyBlockSize,
    BulkKey,
    BulkIV,
    BulkNonce,
    BulkAdditionalData,
    cipherAllowedForVersion,
    hasMAC,
    hasRecordIV,
    elemCipher,
    intersectCiphers,
    findCipher,
) where

import Network.TLS.Crypto (Hash (..), hashDigestSize)
import Network.TLS.Imports
import Network.TLS.Types

data BulkState
    = BulkStateStream BulkStream
    | BulkStateBlock BulkBlock
    | BulkStateAEAD BulkAEAD
    | BulkStateUninitialized

instance Show BulkState where
    show (BulkStateStream _) = "BulkStateStream"
    show (BulkStateBlock _) = "BulkStateBlock"
    show (BulkStateAEAD _) = "BulkStateAEAD"
    show BulkStateUninitialized = "BulkStateUninitialized"

bulkInit :: Bulk -> BulkDirection -> BulkKey -> BulkState
bulkInit bulk direction key =
    case bulkF bulk of
        BulkBlockF ini -> BulkStateBlock (ini direction key)
        BulkStreamF ini -> BulkStateStream (ini direction key)
        BulkAeadF ini -> BulkStateAEAD (ini direction key)

hasMAC, hasRecordIV :: BulkFunctions -> Bool
hasMAC (BulkBlockF _) = True
hasMAC (BulkStreamF _) = True
hasMAC (BulkAeadF _) = False
hasRecordIV = hasMAC

cipherKeyBlockSize :: Cipher -> Int
cipherKeyBlockSize cipher = 2 * (hashDigestSize (cipherHash cipher) + bulkIVSize bulk + bulkKeySize bulk)
  where
    bulk = cipherBulk cipher

-- | Check if a specific 'Cipher' is allowed to be used
-- with the version specified
cipherAllowedForVersion :: Version -> Cipher -> Bool
cipherAllowedForVersion ver cipher =
    case cipherMinVer cipher of
        Nothing -> ver < TLS13
        Just cVer -> cVer <= ver && (ver < TLS13 || cVer >= TLS13)

eqCipher :: CipherID -> Cipher -> Bool
eqCipher cid c = cipherID c == cid

elemCipher :: [CipherId] -> Cipher -> Bool
elemCipher cids c = cid `elem` cids
  where
    cid = CipherId $ cipherID c

intersectCiphers :: [CipherId] -> [Cipher] -> [Cipher]
intersectCiphers peerCiphers myCiphers = filter (elemCipher peerCiphers) myCiphers

findCipher :: CipherID -> [Cipher] -> Maybe Cipher
findCipher cid = find $ eqCipher cid
