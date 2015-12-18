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
* supported versions: SSL3, TLS1.0, TLS1.1, TLS1.2
* key exchange supported: RSA, DHE-RSA, DHE-DSS
* bulk algorithm supported: any stream or block ciphers
* supported extensions: secure renegotiation, next protocol negotiation (draft 2), server name indication

Common Issues
=============

The tools mentioned below are all available from the tls-debug package.

Certificate issues
------------------

It's useful to run the following command, which will connect to the destination and
retrieve the certificate chained used.

    tls-retrievecertificate -d <destination> -p <port> -v -c

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

TLS issues
----------

When having unknown issues with TLS, if your protocol is HTTP based it's useful to use tls-simpleclient from the
tls-debug package.

    tls-simpleclient -d -v <www.myserver.com> <port>

This provides useful information for debugging issues related to TLS.
