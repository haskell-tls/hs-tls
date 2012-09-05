-- |
-- Module      : Network.TLS.Record
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- The Record Protocol takes messages to be transmitted, fragments the
-- data into manageable blocks, optionally compresses the data, applies
-- a MAC, encrypts, and transmits the result.  Received data is
-- decrypted, verified, decompressed, reassembled, and then delivered to
-- higher-level clients.
--
module Network.TLS.Record
        ( Record(..)
        , Fragment
        , fragmentGetBytes
        , fragmentPlaintext
        , fragmentCiphertext
        , recordToRaw
        , rawToRecord
        , recordToHeader
        , Plaintext
        , Compressed
        , Ciphertext
        , engageRecord
        , disengageRecord
        ) where

import Network.TLS.Record.Types
import Network.TLS.Record.Engage
import Network.TLS.Record.Disengage
