#!/bin/sh

make build-openssl-server
stack ghc --package utf8-string test-scripts/TestClient.hs
#ghc -threaded -DUSE_CABAL --make test-scripts/TestClient && echo "BUILDING TEST OK" || echo "BUILDING TEST FAILED"
if [ -x test-scripts/TestClient ]; then touch debug.log; ./test-scripts/TestClient debug.log; cat debug.log; fi
