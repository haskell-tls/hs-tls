haskell TLS
===========

[![Build Status](https://travis-ci.org/vincenthz/hs-tls.png?branch=master)](https://travis-ci.org/vincenthz/hs-tls)
[![BSD](http://b.repl.ca/v1/license-BSD-blue.png)](http://en.wikipedia.org/wiki/BSD_licenses)
[![Haskell](http://b.repl.ca/v1/language-haskell-lightgrey.png)](http://haskell.org)

This library provides native Haskell TLS and SSL protocol implementation for server and client.

Description
-----------

This provides a high-level implementation of a sensitive security protocol,
eliminating a common set of security issues through the use of the advanced
type system, high level constructions and common Haskell features.

Features
--------

* tiny codebase (more than 20 times smaller than OpenSSL, and 10 times smaller than gnuTLS)
* client certificates
* permissive license: BSD3
* supported versions: SSL3, TLS1.0, TLS1.1, TLS1.2, TLS1.3
* key exchange supported: RSA, DHE-RSA, DHE-DSS, ECDHE-RSA, ECDHE-ECDSA
* diffie-hellman groups: finite fields, elliptic curves P-256, P-384, P-521, X25519, X448
* bulk algorithm supported: any stream or block ciphers
* supported extensions: secure renegotiation, application-layer protocol
  negotiation, extended master secret, server name indication

Common Issues
=============

The tools mentioned below are all available from the tls-debug package.

Certificate issues
------------------

It's useful to run the following command, which will connect to the destination and
retrieve the certificate chained used.

    tls-retrievecertificate <destination> <port> --chain --verify

As an output it will print every certificate in the chain and will give the issuer and subjects of each.
It creates a chain where issuer of certificate is the subject of the next certificate part of the chain:

    (subject #1, issuer #2) -> (subject #2, issuer #3) -> (subject #3, issuer #3)

A "CA is unknown" error indicates that your system doesn't have a certificate in
the trusted store belonging to any of the node of the chain.

You can list the certificates available on your system, as detected by tls running the following command (from the `x509-util` package):

    x509-util system

If this command return 0 certificates, it's likely that you don't have any certificates installed,
or that your system is storing certificates in an un-expected place. All TLS operations will result
in "CA is unknown" errors.

# Usage of `tls-simpleclient`

`tls-simpleclient` takes a server name and optionally a port number then generates HTTP/1.1 GET.

- `--tls13`: enabling TLS 1.3
- `-v`: verbose mode to tell TLS 1.3 handshake mode
- `-O` <file>: logging received HTML to the file
- `--http1.1`: ensuring that HTTP/1.1 is used instead of HTTP/1.0
- `--no-valid`: skipping verification of a server certificate

## TLS 1.3 full negotiation

Specify `-g x25519` to not trigger HelloRetryRequest.

```
% tls-simpleclient --tls13 -v --no-valid -O html-log.txt --http1.1 -g x25519 127.0.0.1 443
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

## TLS 1.3 HelloRetryRequest (HRR)

The first value of `-g` is used for key-share.  To trigger HRR, add in first
position a value which will not be accepted by the server, for example use
`ffdhe2048,x25519,p256`.

```
% tls-simpleclient --tls13 -v --no-valid -O html-log.txt --http1.1 -g ffdhe2048,x25519,p256 127.0.0.1 443
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

## Pre-Shared Key

Specify `--session`. The client stores a ticket in the memory and tries to make a new connection with the ticket. Note that a proper keyshare is selected on the second try to avoid HRR.

```
% tls-simpleclient --tls13 -v --no-valid -O html-log.txt --http1.1 --session 127.0.0.1 443
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

## 0RTT

Use `-Z` to specify a file containing early-data. "0RTT is accepted" indicates that 0RTT is succeded.

```
% cat early-data.txt
GET / HTTP/1.1
Host: 127.0.0.1

% tls-simpleclient --tls13 -v --no-valid -O html-log.txt --http1.1 --session -Z early-data.txt 127.0.0.1 443
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
