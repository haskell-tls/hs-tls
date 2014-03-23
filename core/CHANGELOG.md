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
