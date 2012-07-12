-- |
-- Module      : Network.TLS.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Types
    ( Version(..)
    , SessionID
    , SessionData(..)
    , CipherID
    , CompressionID
    ) where

import Data.ByteString (ByteString)
import Data.Word

-- | Versions known to TLS
--
-- SSL2 is just defined, but this version is and will not be supported.
data Version = SSL2 | SSL3 | TLS10 | TLS11 | TLS12 deriving (Show, Eq, Ord)

-- | A session ID
type SessionID = ByteString

-- | Session data to resume
data SessionData = SessionData
        { sessionVersion :: Version
        , sessionCipher  :: CipherID
        , sessionSecret  :: ByteString
        }

type CipherID = Word16
type CompressionID = Word8
