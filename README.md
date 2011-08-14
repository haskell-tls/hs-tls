haskell TLS
===========

This library provide native Haskell TLS and SSL protocol implementation for server and client.

Description
-----------

This provides a high-level implementation of a sensitive security protocol,
eliminating a common set of security issues through the use of the advanced
type system, high level constructions and common Haskell features.

Only core protocol available here, have a look at the tls-extra package for
default ciphers, compressions and certificates functions.

Features
--------

* tiny code base (more than 20 times smaller than openSSL, and 10 times smaller than gnuTLS)
* permissive license: BSD3
* supported versions: SSL3, TLS1.0, TLS1.1.
* key exchange supported: only RSA.
* bulk algorithm supported: any stream or block ciphers.
* supported extensions: secure renegociation

