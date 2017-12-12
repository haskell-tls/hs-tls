module HexDump
    ( hexdump
    ) where

import qualified Data.ByteString as B

import Imports

hexdump :: String -> ByteString -> [String]
hexdump pre b = disptable (defaultConfig { configRowLeft = pre ++ "  | " } ) $ B.unpack b

data BytedumpConfig = BytedumpConfig
    { configRowSize      :: Int    -- ^ number of bytes per row.
    , configRowGroupSize :: Int    -- ^ number of bytes per group per row.
    , configRowGroupSep  :: String -- ^ string separating groups.
    , configRowLeft      :: String -- ^ string on the left of the row.
    , configRowRight     :: String -- ^ string on the right of the row.
    , configCellSep      :: String -- ^ string separating cells in row.
    , configPrintChar    :: Bool   -- ^ if the printable ascii table is displayed.
    } deriving (Show,Eq)

defaultConfig :: BytedumpConfig
defaultConfig = BytedumpConfig
    { configRowSize      = 16
    , configRowGroupSize = 8
    , configRowGroupSep  = " : "
    , configRowLeft      = " | "
    , configRowRight     = " | "
    , configCellSep      = " "
    , configPrintChar    = True
    }

disptable :: BytedumpConfig -> [Word8] -> [String]
disptable _   [] = []
disptable cfg x  =
    let (pre, post) = splitAt (configRowSize cfg) x
    in tableRow pre : disptable cfg post
  where
        tableRow row =
            let l  = splitMultiple (configRowGroupSize cfg) $ map hexString row in
            let lb = intercalate (configRowGroupSep cfg) $ map (intercalate (configCellSep cfg)) l in
            let rb = map printChar row in
            let rowLen = 2 * configRowSize cfg
                       + (configRowSize cfg - 1) * length (configCellSep cfg)
                       + ((configRowSize cfg `div` configRowGroupSize cfg) - 1) * length (configRowGroupSep cfg) in
            configRowLeft cfg ++ lb ++ replicate (rowLen - length lb) ' ' ++ configRowRight cfg ++ (if configPrintChar cfg then rb else "")

        splitMultiple _ [] = []
        splitMultiple n l  = let (pre, post) = splitAt n l in pre : splitMultiple n post

        printChar :: Word8 -> Char
        printChar w
            | w >= 0x20 && w < 0x7f = toEnum $ fromIntegral w
            | otherwise             = '.'

        hex :: Int -> Char
        hex 0  = '0'
        hex 1  = '1'
        hex 2  = '2'
        hex 3  = '3'
        hex 4  = '4'
        hex 5  = '5'
        hex 6  = '6'
        hex 7  = '7'
        hex 8  = '8'
        hex 9  = '9'
        hex 10 = 'a'
        hex 11 = 'b'
        hex 12 = 'c'
        hex 13 = 'd'
        hex 14 = 'e'
        hex 15 = 'f'
        hex _  = ' '

        {-# INLINE hexBytes #-}
        hexBytes :: Word8 -> (Char, Char)
        hexBytes w = (hex h, hex l) where (h,l) = (fromIntegral w) `divMod` 16

        -- | Dump one byte into a 2 hexadecimal characters.
        hexString :: Word8 -> String
        hexString i = [h,l] where (h,l) = hexBytes i

