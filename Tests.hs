{-# LANGUAGE CPP #-}

import qualified Tests.Marshal as Marshal
import qualified Tests.Connection as Connection
import qualified Tests.Ciphers as Ciphers

main = do
	Marshal.runTests
	Ciphers.runTests
	Connection.runTests
