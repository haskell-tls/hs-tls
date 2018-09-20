-- |
-- Module      : Network.TLS.Record.Types13
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--

module Network.TLS.Record.Types13
        ( Record13(..)
        , rawToRecord13
        ) where

import Network.TLS.Struct
import Network.TLS.Record.Types (Header(..))
import Network.TLS.Imports

-- | Represent a TLS record.
data Record13 = Record13 !ProtocolType !Version ByteString deriving (Show,Eq)

-- | turn a header and a fragment into a record
rawToRecord13 :: Header -> ByteString -> Record13
rawToRecord13 (Header pt ver _) = Record13 pt ver
-- the second arg should be TLS12.
