## Version 1.5.4

- Restore interoperability with early Java 6
  [#422](https://github.com/vincenthz/hs-tls/pull/422)
- Test cleanups for timeout and async usage
  [#416](https://github.com/vincenthz/hs-tls/pull/416)

## Version 1.5.3

- Additional verification regarding EC signatures
  [#412](https://github.com/vincenthz/hs-tls/pull/412)
- Fixing ALPN
  [#411](https://github.com/vincenthz/hs-tls/pull/411)
- Check SSLv3 padding length
  [#410](https://github.com/vincenthz/hs-tls/pull/410)
- Exposing getClientCertificateChain
  [#407](https://github.com/vincenthz/hs-tls/pull/407)
- Extended Master Secret
  [#406](https://github.com/vincenthz/hs-tls/pull/406)
- Brushing up the documentation
  [#404](https://github.com/vincenthz/hs-tls/pull/404)
  [#408](https://github.com/vincenthz/hs-tls/pull/408)
- Improving tests
  [#403](https://github.com/vincenthz/hs-tls/pull/403)
- Avoid calling onServerNameIndication twice with HRR
  [#402](https://github.com/vincenthz/hs-tls/pull/402)
- Enable X448 and FFDHE groups
  [#401](https://github.com/vincenthz/hs-tls/pull/401)
- Refactoring
  [#400](https://github.com/vincenthz/hs-tls/pull/400)
  [#399](https://github.com/vincenthz/hs-tls/pull/399)

## Version 1.5.2

- Enabled TLS 1.3 by default [#398](https://github.com/vincenthz/hs-tls/pull/398)
- Avoid handshake failure with small RSA keys [#394](https://github.com/vincenthz/hs-tls/pull/394)

NOTES:

- Starting with tls-1.5.0, the parameter `supportedVersions` contains values
  ordered by decreasing preference, so typically the higher versions first.
  This departs from code samples previously available.  For maximum
  interoperability, users overriding the default value should verify and adapt
  their code.

## Version 1.5.1

- Post-handshake authentication [#363](https://github.com/vincenthz/hs-tls/pull/363)
- Middlebox compatibility [#386](https://github.com/vincenthz/hs-tls/pull/386)
- Verification and configuration of session-ticket lifetime [#373](https://github.com/vincenthz/hs-tls/pull/373)
- Fixing memory leak [#366](https://github.com/vincenthz/hs-tls/pull/366)
- Don't send 0-RTT data when ticket is expired [#370](https://github.com/vincenthz/hs-tls/pull/370)
- Handshake packet fragmentation [#371](https://github.com/vincenthz/hs-tls/pull/371)
- Fix SSLv2 deprecated header [#383](https://github.com/vincenthz/hs-tls/pull/383)
- Other improvements to TLS 1.3 and RFC conformance [#368](https://github.com/vincenthz/hs-tls/pull/368) [#372](https://github.com/vincenthz/hs-tls/pull/372) [#375](https://github.com/vincenthz/hs-tls/pull/375) [#376](https://github.com/vincenthz/hs-tls/pull/376) [#377](https://github.com/vincenthz/hs-tls/pull/377) [#378](https://github.com/vincenthz/hs-tls/pull/378) [#380](https://github.com/vincenthz/hs-tls/pull/380) [#382](https://github.com/vincenthz/hs-tls/pull/382) [#385](https://github.com/vincenthz/hs-tls/pull/385) [#387](https://github.com/vincenthz/hs-tls/pull/387) [#388](https://github.com/vincenthz/hs-tls/pull/388)

## Version 1.5.0

- Add and enable AES CCM ciphers [#271](https://github.com/vincenthz/hs-tls/pull/271) [#287](https://github.com/vincenthz/hs-tls/pull/287)
- Verify certificate key usage [#274](https://github.com/vincenthz/hs-tls/pull/274) [#301](https://github.com/vincenthz/hs-tls/pull/301)
- TLS 1.3 support [#278](https://github.com/vincenthz/hs-tls/pull/278) [#279](https://github.com/vincenthz/hs-tls/pull/279) [#280](https://github.com/vincenthz/hs-tls/pull/280) [#283](https://github.com/vincenthz/hs-tls/pull/283) [#298](https://github.com/vincenthz/hs-tls/pull/298) [#331](https://github.com/vincenthz/hs-tls/pull/331) [#290](https://github.com/vincenthz/hs-tls/pull/290) [#314](https://github.com/vincenthz/hs-tls/pull/314)
- Enable RSASSA-PSS [#280](https://github.com/vincenthz/hs-tls/pull/280) [#353](https://github.com/vincenthz/hs-tls/pull/353)
- Add and enable ChaCha20-Poly1305 ciphers [#287](https://github.com/vincenthz/hs-tls/pull/287) [#340](https://github.com/vincenthz/hs-tls/pull/340)
- Certificate selection with extension "signature_algorithms_cert" [#302](https://github.com/vincenthz/hs-tls/pull/302)
- Preventing Logjam attack [#300](https://github.com/vincenthz/hs-tls/pull/300)
- Downgrade protection [#308](https://github.com/vincenthz/hs-tls/pull/308)
- Support for EdDSA certificates [#328](https://github.com/vincenthz/hs-tls/pull/328) [#353](https://github.com/vincenthz/hs-tls/pull/353)
- Key logging [#317](https://github.com/vincenthz/hs-tls/pull/317)
- Thread safety for writes [#329](https://github.com/vincenthz/hs-tls/pull/329)
- Verify signature schemes and (EC)DHE groups received [#337](https://github.com/vincenthz/hs-tls/pull/337) [#338](https://github.com/vincenthz/hs-tls/pull/338)
- Throw BadRecordMac when the decrypted record has invalid format [#347](https://github.com/vincenthz/hs-tls/pull/347)
- Improve documentation format [#341](https://github.com/vincenthz/hs-tls/pull/341) [#343](https://github.com/vincenthz/hs-tls/pull/343)
- Fix recvClientData with single Handshake packet [#352](https://github.com/vincenthz/hs-tls/pull/352)
- Decrease memory footprint of SessionData values [#354](https://github.com/vincenthz/hs-tls/pull/354)

FEATURES:

- TLS version 1.3 is available with most features but is not enabled by default.
  One notable omission is post-handshake authentication.  Scenarios where
  servers previously used renegotiation to conditionally request a certificate
  are not possible yet when `TLS13` is negotiated.  Users may enable the version
  in `supportedVersions` only when sure post-handshake authentication is not
  required.

API CHANGES:

- `SessionManager` implementations need to provide a `sessionResumeOnlyOnce`
  function to accomodate resumption scenarios with 0-RTT data.  The function is
  called only on the server side.
- Data type `SessionData` is extended with four new fields for TLS version 1.3.
  `SessionManager` implementations that serializes/deserializes `SessionData`
  values must deal with the new fields.
- New configuration parameters and constructors are added for TLS version 1.3
  but the API change should be backward compatible for most use-cases.
- Function `cipherExchangeNeedMoreData` has been removed.

## Version 1.4.1

- Enable X25519 in default parameters [#265](https://github.com/vincenthz/hs-tls/pull/265)
- Checking EOF in bye [#262](https://github.com/vincenthz/hs-tls/pull/262)
- Improving validation in DH key exchange [#256](https://github.com/vincenthz/hs-tls/pull/256)
- Handle TCP reset during handshake [#251](https://github.com/vincenthz/hs-tls/pull/251)
- Accepting hlint suggestions.

## Version 1.4.0

- Wrap renegotiation failures with HandshakeFailed [#237](https://github.com/vincenthz/hs-tls/pull/237)
- Improve selection of server certificate and use "signature_algorithms" extension [#236](https://github.com/vincenthz/hs-tls/pull/236)
- Change Bytes to ByteString and deprecate the Bytes type alias [#230](https://github.com/vincenthz/hs-tls/pull/230)
- Session compression and SNI [#223](https://github.com/vincenthz/hs-tls/pull/223)
- Deprecating ciphersuite_medium. Putting WARNING to ciphersuite_all since this includes RC4 [#153](https://github.com/vincenthz/hs-tls/pull/153) [#222](https://github.com/vincenthz/hs-tls/pull/222)
- Removing NPN [#214](https://github.com/vincenthz/hs-tls/pull/214)
- Supporting RSAPSS defined in TLS 1.3 [#207](https://github.com/vincenthz/hs-tls/pull/207)
- Supporting X25519 and X448 in the IES style. [#205](https://github.com/vincenthz/hs-tls/pull/205)
- Strip leading zeros in DHE premaster secret [#201](https://github.com/vincenthz/hs-tls/pull/201)

FEATURES:

- RSASSA-PSS signatures can be enabled with `supportedHashSignatures`.  This
  uses assignments from TLS 1.3, for example `(HashIntrinsic, SignatureRSApssSHA256)`.
- Diffie-Hellman with elliptic curves X25519 and X448: This can be enabled with
  `supportedGroups`, which also gives control over curve preference.
- ECDH with curve P-256 now uses optimized C implementation from package `cryptonite`.

API CHANGES:

- Cipher list `ciphersuite_medium` is now deprecated, users are advised to use
  `ciphersuite_default` or `ciphersuite_strong`.  List `ciphersuite_all` is kept
  for compatibility with old servers but this is discouraged and generates a
  warning (this includes RC4 ciphers, see [#153](https://github.com/vincenthz/hs-tls/pull/153)
  for reference).
- Support for NPN (Next Protocol Negotiation) has been removed. The replacement
  is ALPN (Application-Layer Protocol Negotiation).
- Data type `SessionData` now contains fields for compression algorithm and
  client SNI.  A `SessionManager` implementation that serializes/deserializes
  `SessionData` values must deal with the new fields.
- Module `Network.TLS` exports a type alias named `Bytes` which is now deprecated.
  The replacement is to use strict `ByteString` directly.

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
