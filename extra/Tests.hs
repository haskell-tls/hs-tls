import qualified Tests.Connection as Connection
import qualified Tests.Ciphers as Ciphers

main = do
	Ciphers.runTests
	Connection.runTests
