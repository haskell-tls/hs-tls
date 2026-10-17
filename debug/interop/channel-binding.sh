#!/usr/bin/env bash
# Does this library's tls-exporter channel binding agree with another
# implementation's?
#
# RFC 9266's binding is RFC 8446's exporter under a fixed label, and the
# exporter has a step -- Derive-Secret over the empty transcript -- that is
# easy to get wrong in a way nothing local notices: both ends of an hs-tls
# connection compute the same wrong value and agree with each other.  It took
# a second implementation to see it.  So one runs here: tls-simpleserver
# against `openssl s_client -keymatexport`, and the two hexadecimal strings
# have to be the same.
#
# Usage: debug/interop/channel-binding.sh [builddir]
set -euo pipefail

here=$(cd "$(dirname "$0")/../.." && pwd)
builddir=${1:-dist-newstyle}
port=$((40000 + RANDOM % 20000))
work=$(mktemp -d "${TMPDIR:-/tmp}/hs-tls-cb.XXXXXX")
server_pid=

cleanup() {
    [ -n "$server_pid" ] && kill -INT "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

openssl version

cd "$here"
cabal build --builddir="$builddir" -v0 tls-debug:exe:tls-simpleserver
server=$(cabal list-bin --builddir="$builddir" tls-debug:exe:tls-simpleserver)

"$server" --verbose --tls13 --no-version-downgrade \
    --certificate test-certs/server.rsa.crt \
    --key test-certs/server.rsa.key "$port" > "$work/server.log" 2>&1 &
server_pid=$!

# The server needs a moment to bind; s_client exits non-zero until it does.
connected=
for _ in $(seq 1 50); do
    if openssl s_client -connect "127.0.0.1:$port" -tls1_3 \
        -ciphersuites TLS_AES_128_GCM_SHA256 \
        -keymatexport EXPORTER-Channel-Binding -keymatexportlen 32 \
        </dev/null > "$work/openssl.log" 2>&1; then
        connected=1
        break
    fi
    sleep 0.2
done
[ -n "$connected" ] || { echo "could not connect to the server"; cat "$work/server.log"; exit 1; }

ours=
for _ in $(seq 1 50); do
    ours=$(awk '/^tls-exporter: / { print $2; exit }' "$work/server.log")
    [ -n "$ours" ] && break
    sleep 0.2
done
theirs=$(awk '/Keying material:/ { print tolower($3); exit }' "$work/openssl.log")

echo "hs-tls  $ours"
echo "openssl $theirs"

if [ -z "$ours" ] || [ -z "$theirs" ]; then
    echo "one side produced nothing"
    cat "$work/server.log" "$work/openssl.log"
    exit 1
fi
if [ "$ours" != "$theirs" ]; then
    echo "::error::the tls-exporter channel bindings differ"
    exit 1
fi
echo "ok   the two agree"
