all:
	echo "reinstall | tests"

.PHONY: reinstall
reinstall:
	(cd core; cabal install --force-reinstalls --enable-tests; cd ../debug; cabal install --force-reinstalls)

.PHONY: tests
tests: test-scripts/TestClient
	./test-scripts/TestClient

.PHONY: test-scripts/TestClient
test-scripts/TestClient:
	ghc -threaded --make test-scripts/TestClient
