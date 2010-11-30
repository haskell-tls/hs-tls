{-# LANGUAGE CPP #-}

import qualified Tests.Marshal as Marshal
import qualified Tests.Connection as Connection

main = do
	Marshal.runTests
	Connection.runTests
