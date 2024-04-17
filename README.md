![GitHub Actions status](https://github.com/haskell-tls/hs-tls/workflows/Haskell%20CI/badge.svg)

# Haskell TLS

* `tls` :: library for TLS 1.2/1.3 server and client purely in Haskell
* `tls-session-manager` :: library for in-memory session DB and session ticket.

If the `devel` flag is specified to `tls`, `tls-client` and `tls-server` are also built.

## Usage of `tls-client`

```
Usage: quic-client [OPTION] addr port [path]
  -d           --debug                print debug info
  -v           --show-content         print downloaded content
  -l <file>    --key-log-file=<file>  a file to store negotiated secrets
  -g <groups>  --groups=<groups>      specify groups
  -e           --validate             validate server's certificate
  -R           --resumption           try session resumption
  -Z           --0rtt                 try sending early data
  -S           --hello-retry          try client hello retry
  -2           --tls12                use TLS 1.2
  -3           --tls13                use TLS 1.3

  <groups> = ffdhe2048,ffdhe3072,ffdhe4096,ffdhe6144,ffdhe8192,p256,p384,p521,x25519,x448
```

### TLS 1.3 full negotiation

```
% tls-client -3 -d 127.0.0.1 443
------------------------
Version: TLS1.3
Cipher: TLS_AES_256_GCM_SHA384
Compression: 0
Groups: X25519
Handshake mode: FullHandshake
Early data accepted: False
Result: (H) handshake ... OK
Result: (1) HTTP/1.1 transaction ... OK
```

### TLS 1.3 HelloRetryRequest (HRR)

```
% tls-client -3 -d 127.0.0.1 443 -S
------------------------
Version: TLS1.3
Cipher: TLS_AES_256_GCM_SHA384
Compression: 0
Groups: X25519
Handshake mode: HelloRetryRequest
Early data accepted: False
Result: (S) retry ... OK
```

### Resumption (PSK: Pre-Shared Key)

```
% tls-client -3 -d 127.0.0.1 443 -R
------------------------
Version: TLS1.3
Cipher: TLS_AES_256_GCM_SHA384
Compression: 0
Groups: X25519
Handshake mode: FullHandshake
Early data accepted: False
<<<< next connection >>>>
------------------------
Version: TLS1.3
Cipher: TLS_AES_256_GCM_SHA384
Compression: 0
Groups: X25519
Handshake mode: PreSharedKey
Early data accepted: False
Result: (R) TLS resumption ... OK
```

### 0-RTT on resumption

```
% tls-client -3 -d 127.0.0.1 443 -Z
------------------------
Version: TLS1.3
Cipher: TLS_AES_256_GCM_SHA384
Compression: 0
Groups: X25519
Handshake mode: FullHandshake
Early data accepted: False
<<<< next connection >>>>
------------------------
Version: TLS1.3
Cipher: TLS_AES_256_GCM_SHA384
Compression: 0
Groups: X25519
Handshake mode: RTT0
Early data accepted: True
Result: (Z) 0-RTT ... OK
```
