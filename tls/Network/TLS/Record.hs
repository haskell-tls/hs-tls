-- | The Record Protocol takes messages to be transmitted, fragments
-- the data into manageable blocks, optionally compresses the data,
-- applies a MAC, encrypts, and transmits the result.  Received data
-- is decrypted, verified, decompressed, reassembled, and then
-- delivered to higher-level clients.
module Network.TLS.Record (
    Record (..),

    -- * Fragment manipulation types
    Fragment,
    fragmentGetBytes,
    fragmentPlaintext,
    fragmentCiphertext,
    recordToRaw,
    rawToRecord,
    recordToHeader,
    Plaintext,
    Ciphertext,

    -- * Engage and disengage from the record layer
    engageRecord,
    disengageRecord,

    -- * State tracking
    RecordM,
    runRecordM,
    RecordState (..),
    newRecordState,
    getRecordVersion,
    setRecordIV,
) where

import Network.TLS.Record.Disengage
import Network.TLS.Record.Engage
import Network.TLS.Record.State
import Network.TLS.Record.Types
