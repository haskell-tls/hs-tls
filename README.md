![GitHub Actions status](https://github.com/haskell-tls/hs-tls/workflows/Haskell%20CI/badge.svg)[![Nix Flake](https://github.com/haskell-tls/hs-tls/actions/workflows/nix-flake.yml/badge.svg)](https://github.com/haskell-tls/hs-tls/actions/workflows/nix-flake.yml)

# Haskell TLS

* `tls` :: library for TLS 1.2/1.3 server and client purely in Haskell
* `tls-session-manager` :: library for in-memory session DB and session ticket.

If the `devel` flag is specified to `tls`, `client` and `server` are also built.

## Usage of `client`

`client` takes a server name and optionally a port number then generates HTTP/1.1 GET.

- `--tls13`: enabling TLS 1.3
- `-v`: verbose mode to tell TLS 1.3 handshake mode
- `-O` <file>: logging received HTML to the file
- `--http1.1`: ensuring that HTTP/1.1 is used instead of HTTP/1.0
- `--no-valid`: skipping verification of a server certificate

### TLS 1.3 full negotiation

Specify `-g x25519` to not trigger HelloRetryRequest.

```
% client --tls13 -v --no-valid -O html-log.txt --http1.1 -g x25519 127.0.0.1 443
sending query:
GET / HTTP/1.1
Host: 127.0.0.1



version: TLS13
cipher: AES128GCM-SHA256
compression: 0
group: X25519
handshake emode: FullHandshake
early data accepted: False
server name indication: 127.0.0.1
```

### TLS 1.3 HelloRetryRequest (HRR)

The first value of `-g` is used for key-share.  To trigger HRR, add in first
position a value which will not be accepted by the server, for example use
`ffdhe2048,x25519,p256`.

```
% client --tls13 -v --no-valid -O html-log.txt --http1.1 -g ffdhe2048,x25519,p256 127.0.0.1 443
sending query:
GET / HTTP/1.1
Host: 127.0.0.1



version: TLS13
cipher: AES128GCM-SHA256
compression: 0
group: X25519
handshake emode: HelloRetryRequest
early data accepted: False
server name indication: 127.0.0.1
```

### Pre-Shared Key

Specify `--session`. The client stores a ticket in the memory and tries to make a new connection with the ticket. Note that a proper keyshare is selected on the second try to avoid HRR.

```
% client --tls13 -v --no-valid -O html-log.txt --http1.1 --session 127.0.0.1 443
sending query:
GET / HTTP/1.1
Host: 127.0.0.1



version: TLS13
cipher: AES128GCM-SHA256
compression: 0
group: X25519
handshake emode: HelloRetryRequest
early data accepted: False
server name indication: 127.0.0.1

Resuming the session...
sending query:
GET / HTTP/1.1
Host: 127.0.0.1



version: TLS13
cipher: AES128GCM-SHA256
compression: 0
group: X25519
handshake emode: PreSharedKey
early data accepted: False
server name indication: 127.0.0.1
```

### 0RTT

Use `-Z` to specify a file containing early-data. "0RTT is accepted" indicates that 0RTT is succeded.

```
% cat early-data.txt
GET / HTTP/1.1
Host: 127.0.0.1

% client --tls13 -v --no-valid -O html-log.txt --http1.1 --session -Z early-data.txt 127.0.0.1 443
sending query:
GET / HTTP/1.1
Host: 127.0.0.1



version: TLS13
cipher: AES128GCM-SHA256
compression: 0
group: X25519
handshake emode: HelloRetryRequest
early data accepted: False
server name indication: 127.0.0.1

Resuming the session...
sending query:
GET / HTTP/1.1
Host: 127.0.0.1



version: TLS13
cipher: AES128GCM-SHA256
compression: 0
group: X25519
handshake emode: RTT0
early data accepted: True
server name indication: 127.0.0.1
```
