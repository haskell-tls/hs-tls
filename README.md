![GitHub Actions status](https://github.com/haskell-tls/hs-tls/workflows/Haskell%20CI/badge.svg)

# Haskell TLS

* `tls` :: library for TLS 1.2/1.3 server and client purely in Haskell
* `tls-session-manager` :: library for in-memory session DB and session ticket.
* `ech-config` :: library for the configuration of Encrypted Client Hello, to glue DNS and TLS.

For the `tls-client` and `tls-server` commands, see [tls/USAGE.md](tls/USAGE.md).

## Security

This section says what `tls` protects by default, what it does not
promise, and what is left to the application.  The library has not been
audited by a third party.

### Defaults

* Only TLS 1.3 and TLS 1.2 are negotiated.  TLS 1.1 and earlier are not
  supported.
* The default cipher suites (`ciphersuite_default`) are AEAD only.  CBC
  suites are available from `Network.TLS.Extra.CipherCBC` and must be
  enabled explicitly.
* TLS 1.2 requires the Extended Main Secret (RFC 7627).
* Secure renegotiation (RFC 5746) is on, and renegotiation initiated by a
  client is refused.
* 0-RTT is off on both sides.
* The key exchange groups include the hybrid X25519MLKEM768.
* The number of consecutive KeyUpdate messages a peer may send is limited.

### Certificates

* A client validates the server's certificate chain and host name with
  `crypton-x509-validation` and the system certificate store
  (`validateDefault`).
* Revocation is not checked: neither OCSP nor CRLs are used.  Short-lived
  certificates are the intended answer to revocation.

### Side channels

* The cryptographic primitives come from `crypton`, which implements them
  in constant time.
* The record layer compares MACs in constant time and pads the MAC
  computation of CBC records against Lucky Thirteen.
* The Haskell code in `tls`, such as the record layer, runs with garbage
  collection and lazy evaluation and cannot be guaranteed to run in
  constant time.  This is one reason why CBC is off by default.

### Testing

* Unit and property tests, including tests that modify records on the wire.
* [tlsfuzzer](https://github.com/tlsfuzzer/tlsfuzzer) is run against
  `tls-server` every week.
* The channel bindings are checked against OpenSSL in CI.  ECH has been
  tested with DEfO OpenSSL, picotls, BoringSSL and NSS.

### Left to the application

* 0-RTT data can be replayed.  A server that accepts it must make sure the
  data is safe to process twice.  The server asks the session manager to
  resume a ticket only once for 0-RTT, which `tls-session-manager` does.
* Enabling CBC suites, or replacing `onServerCertificate` with a weaker
  check, gives up the protections above.
* After session resumption, the client certificate is not available
  ([#600](https://github.com/haskell-tls/hs-tls/issues/600)).
