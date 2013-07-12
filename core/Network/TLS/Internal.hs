{-# OPTIONS_HADDOCK hide #-}
-- |
-- Module      : Network.TLS.Internal
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Internal
    ( module Network.TLS.Struct
    , module Network.TLS.Packet
    , module Network.TLS.Receiving
    , module Network.TLS.Sending
    , sendPacket
    , recvPacket
    ) where

import Network.TLS.Struct
import Network.TLS.Packet
import Network.TLS.Receiving
import Network.TLS.Sending
import Network.TLS.Core (sendPacket, recvPacket)
