## Version 1.3.11

- Using reliable versions of dependent libraries.

## Version 1.3.10

- Selecting a cipher based on "signature_algorithms" [#193](https://github.com/vincenthz/hs-tls/pull/193)
- Respecting the "signature_algorithms" extension [#137](https://github.com/vincenthz/hs-tls/pull/137)
- Fix RSA signature in CertificateVerify with TLS < 1.2 [#189](https://github.com/vincenthz/hs-tls/pull/189)
- Fix ECDSA with TLS 1.0 / TLS 1.1 [#187](https://github.com/vincenthz/hs-tls/pull/187)
- Sending an empty server name from a server if necessary. [#175](https://github.com/vincenthz/hs-tls/pull/175)
- `Network.TLS.Extra` provides Finite Field Diffie-Hellman Ephemeral Parameters in RFC 7919 [#174](https://github.com/vincenthz/hs-tls/pull/174)
- Restore ability to renegotiate[#164](https://github.com/vincenthz/hs-tls/pull/164)

## Version 1.3.9

- Drop support for old GHC.
- Enable sha384 ciphers and provide `ciphersuite_default` as default set of ciphers for common needs [#168](https://github.com/vincenthz/hs-tls/pull/168)
- SNI late checks [#147](https://github.com/vincenthz/hs-tls/pull/147)
- Expose the HasBackend(..) class fully, so that developers can use TLS over their own channels [#149](https://github.com/vincenthz/hs-tls/pull/149)

## Version 1.3.8

- Fix older GHC builds

## Version 1.3.7

- Disable SHA384 based cipher, as they don't work properly yet.

## Version 1.3.6

- Add new ciphers
- Improve some debugging and outputs

## Version 1.3.5

- Fix a bug with ECDHE based cipher where serialization
- Debugging: Add a way to print random seed and a way to side-load a seed for replayability
- Improve tests

## Version 1.3.4

- Fix tests on 32 bits `time_t` machines (time not within bound)
- VirtualHost: Add a way to load credentials related to the hostname used by the client (Julian Beaumont)
- VirtualHost: Expose an API to query which hostname the client has contacted (Julian Beaumont)
- Add a way to disable empty packet that are use for security when
  using old versions + old CBC based cipher (Anton Dessiatov)

## Version 1.3.3

- Add support for Hans (Haskell Network Stack) (Adam Wick)
- Add support for ECDSA signature
- Add support for ECDSA-ECDHE Cipher
- Improve parsing of ECC related structure

## Version 1.3.2

- Add cipher suites for forward secrecy on more clients (Aaron Friel)
- Maintain more handshake information to be queried by protocol (Adam Wick)
- handle SCSV on client and server side (Kazu Yamamoto)
- Cleanup renegotiation logic (Kazu Yamamoto)
- Various testing improvements with the openssl test parts
- Cleanup AEAD handling for future support of other ciphers

## Version 1.3.1

- Repair DHE RSA handling on the cipher by creating signature properly

## Version 1.3.0

- modernize the crypto stack by using cryptonite.

## Version 1.2.18

- add more tests (network, local)
- cleanup cipher / bulk code, certificate verify / creation, and digitall signed handling
- fix handling of DHE ciphers with MS SSL stack that serialize leading zero.

## Version 1.2.17

- Fix an issue of type of key / hash that prevented connection with SChannel.

## Version 1.2.16

- Fix an issue with stream cipher not correctly calculating the internal state,
  resulting systematically in bad record mac failure during handshake

## Version 1.2.15

- support chain certificate in credentials

## Version 1.2.14

- adding ALPN extension
- adding support for AEAD, and particularly AES128-GCM
- Adding support for ECDH
- Do not support SSL3 by default for security reason.
- add EnumSafe8 and 16 for specific sized Enum instance that are safer
- export signatureAndHash parser/encoder
- add a "known" list of extensions
- add SignatureAlgorithms extension
- add Heartbeat extension
- add support for EC curves and point format extensions
- add preliminary SessionTicket extension
- Debug: Add the ability to choose arbitrary cipher in the client hello.

## Version 1.2.13

- Fix compilation with old mtl version

## Version 1.2.12

- Propagate asynchronous exception

## Version 1.2.11

- use hourglass instead of time
- use tasty instead of test-framework
- add travis file
- remove old de-optimisation flag as the bytestring bug is old now and it conflict with cabal check

## Version 1.2.10

- Update x509 dependencies

## Version 1.2.9

- Export TLSParams and HasBackend type names
- Added FlexibleContexts flag required by ghc-7.9
- debug: add support for specifying the timeout length in milliseconds.
- debug: add support for 3DES in simple client

## Version 1.2.8

- add support for 3DES-EDE-CBC-SHA1 (cipher 0xa)

## Version 1.2.7

- repair retrieve certificate validation, and improve fingerprints
- remove groom from dependency
- make RecordM an instance of Applicative
- Fixes the Error_EOF partial pattern match error in exception handling

## Version 1.2.6 (23 Mar 2014)

- Fixed socket backend endless loop when the server does not close connection
  properly at the TLS level with the close notify alert.
- Catch Error_EOF in recvData and return empty data.

## Version 1.2.5 (23 Mar 2014)

- Fixed Server key exchange data being parsed without the correct
  context, leading to not knowing how to parse the structure.
  The bug happens on efficient server that happens to send the ServerKeyXchg
  message together with the ServerHello in the same handshake packet.
  This trigger parsing of all the messages without having set the pending cipher.
  Delay parsing, when this happen, until we know what to do with it.

## Version 1.2.4 (23 Mar 2014)

- Fixed unrecognized name non-fatal alert after client hello.
- Add SSL3 to the supported list of version by default.
- Fix cereal lower bound to 0.4.0 minimum

## Version 1.2.3 (22 Mar 2014)

- Fixed handshake records not being able to span multiples records.
