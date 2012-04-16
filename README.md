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
* permissive license: BSD3.
* supported versions: SSL3, TLS1.0, TLS1.1, TLS1.2.
* key exchange supported: only RSA.
* bulk algorithm supported: any stream or block ciphers.
* supported extensions: secure renegociation

Common Issues
-------------

The tools mentioned below are all available from the tls-debug package.

* Certificate issues

It's useful to run the following command, which will connect to the destination and
retrieve the certificate chained used.

    tls-retrievecertificate -d <destination> -p <port> -v -c

As an output it will print every certificates in the chain and will gives the issuer and subjects of each.
It creates a chain where issuer of certificate is the subject of the next certificate part of the chain:

    (subject #1, issuer #2) -> (subject #2, issuer #3) -> (subject #3, issuer #3)

A "CA is unknown" error indicates that your system doesn't have a certificate in
the trusted store belonging to any of the node of the chain.

