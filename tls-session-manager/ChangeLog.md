# ChangeLog for tls-session-manager

## Unreleased

* Refuse a replayed 0-RTT ticket in the session ticket manager.
  [#634](https://github.com/haskell-tls/hs-tls/pull/634)

## 0.1.2

* Require tls >= 2.4.13 and build the tests with `defaultSessionData`.
  [#607](https://github.com/haskell-tls/hs-tls/pull/607)

## 0.1.1

* Keep a TLS 1.3 session no longer than the lifetime of its ticket.
  [#604](https://github.com/haskell-tls/hs-tls/pull/604)
* Do not resume an expired session before it is pruned.
  [#604](https://github.com/haskell-tls/hs-tls/pull/604)
* Keep deletions and the size limit across pruning.
  [#604](https://github.com/haskell-tls/hs-tls/pull/604)
* Do not drop another session when a key is added again at the limit.
  [#604](https://github.com/haskell-tls/hs-tls/pull/604)
* Expose `Network.TLS.SessionManager.Internal` for testing.
  [#604](https://github.com/haskell-tls/hs-tls/pull/604)

## 0.1.0

* Using "ram" instead of "memory"

## 0.0.9

* Providing newSessionTicketManager' to kill the manager.

## 0.0.8

* Removing "basement".

## 0.0.7

* Naming threads.

## 0.0.6

* Preparing for tls v2.1.

## 0.0.5

* Supporting "tls" v2.0.0.

## 0.0.4

* Supporting "tls" v1.5.3.

## 0.0.3

* Adding Strict and StrictData pragma

## 0.0.2.1

* Supporting "tls" v1.5.0.

## 0.0.2.0

* Using ShortByteString internally to avoid ByteString's fragmentation.
* The default value of dbMaxSize is now 1,000.

## 0.0.1.0

* Supporting sessionResumeOnlyOnce.

## 0.0.0.0
* A first release.
