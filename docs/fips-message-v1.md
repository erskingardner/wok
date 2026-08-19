# FIPS logical-message protocol V1

This protocol carries opaque logical messages over FIPS native datagrams. It
does not add reliability to FIPS V1: complete messages can be lost whenever a
datagram is lost. Its responsibilities are only session establishment,
chunking, bounded reassembly, and in-order delivery of messages that arrive in
full.

All integers are unsigned and encoded in network byte order. Every datagram has
this 38-byte header:

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | Magic: ASCII `WFP1` (`57 46 50 31`) |
| 4 | 1 | Version: `01` |
| 5 | 1 | Kind |
| 6 | 16 | Session identifier/nonce |
| 22 | 8 | Logical message identifier |
| 30 | 2 | Chunk index, zero based |
| 32 | 2 | Chunk count |
| 34 | 4 | Total logical-message length |
| 38 | rest | Payload |

Kinds are `HELLO=1`, `READY=2`, `DATA=3`, `CLOSE=4`, `PING=5`, and `PONG=6`.
`CLOSE`, `PING`, and `PONG` are reserved in V1 and have no behavior. All
control frames have zero message/chunk/length fields and no payload.

The connector chooses a fresh 128-bit session identifier, sends `HELLO`, and
retransmits it with bounded exponential backoff until the setup deadline. The
listener answers each valid `HELLO` with a `READY` carrying the same session
identifier. A connector must not send `DATA` until that matching `READY`
arrives. An old or mismatched `READY` cannot establish a new session.

For `DATA`, every chunk repeats the session, message identifier, chunk count,
and total length, so any chunk can begin reassembly. Message identifiers start
at zero independently in each direction and increase by one. Receivers accept
out-of-order chunks and matching duplicates. Conflicting duplicates or
metadata fail the logical session. Completed later messages wait for all
earlier messages; if the earliest incomplete message or an observed identifier
gap expires, the session fails rather than delivering later Nostr commands out
of order.

The payload capacity is always `flow.max_payload() - 38`. A sender rejects a
flow whose capacity is zero for a non-empty logical message. Implementations
must bound logical-message size, chunk count, incomplete-message count,
aggregate buffered bytes, completed messages waiting for ordered delivery, and
the monotonic lifetime of incomplete messages.

Golden vectors:

```text
HELLO, session 000102030405060708090a0b0c0d0e0f
574650310101000102030405060708090a0b0c0d0e0f00000000000000000000000000000000

DATA, same session, message 1011121314151617, chunk 1/3, total 9, payload "def"
574650310103000102030405060708090a0b0c0d0e0f10111213141516170001000300000009646566
```
