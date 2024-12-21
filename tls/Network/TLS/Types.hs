{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE PatternSynonyms #-}

module Network.TLS.Types (
    module Network.TLS.Types.Cipher,
    module Network.TLS.Types.Secret,
    module Network.TLS.Types.Session,
    module Network.TLS.Types.Version,
    HostName,
    Role (..),
    invertRole,
    Direction (..),
    BigNum (..),
    bigNumToInteger,
    bigNumFromInteger,
) where

import Network.Socket (HostName)

import Network.TLS.Imports
import Network.TLS.Types.Cipher
import Network.TLS.Types.Secret
import Network.TLS.Types.Session
import Network.TLS.Types.Version
import Network.TLS.Util.Serialization

----------------------------------------------------------------

-- | Role
data Role = ClientRole | ServerRole
    deriving (Show, Eq)

invertRole :: Role -> Role
invertRole ClientRole = ServerRole
invertRole ServerRole = ClientRole

----------------------------------------------------------------

-- | Direction
data Direction = Tx | Rx
    deriving (Show, Eq)

----------------------------------------------------------------

newtype BigNum = BigNum ByteString
    deriving (Show, Eq)

bigNumToInteger :: BigNum -> Integer
bigNumToInteger (BigNum b) = os2ip b

bigNumFromInteger :: Integer -> BigNum
bigNumFromInteger i = BigNum $ i2osp i

----------------------------------------------------------------
