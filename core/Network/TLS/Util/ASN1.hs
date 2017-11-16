-- |
-- Module      : Network.TLS.Util.ASN1
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- ASN1 utils for TLS
--
module Network.TLS.Util.ASN1
    ( decodeASN1Object
    , encodeASN1Object
    ) where

import Network.TLS.Imports
import Data.ASN1.Types (fromASN1, toASN1, ASN1Object)
import Data.ASN1.Encoding (decodeASN1', encodeASN1')
import Data.ASN1.BinaryEncoding (DER(..))

-- | Attempt to decode a bytestring representing
-- an DER ASN.1 serialized object into the object.
decodeASN1Object :: ASN1Object a
                 => String
                 -> ByteString
                 -> Either String a
decodeASN1Object name bs =
    case decodeASN1' DER bs of
        Left e     -> Left (name ++ ": cannot decode ASN1: " ++ show e)
        Right asn1 -> case fromASN1 asn1 of
                            Left e      -> Left (name ++ ": cannot parse ASN1: " ++ show e)
                            Right (d,_) -> Right d

-- | Encode an ASN.1 Object to the DER serialized bytestring
encodeASN1Object :: ASN1Object a
                 => a
                 -> ByteString
encodeASN1Object obj = encodeASN1' DER $ toASN1 obj []
