# Known differences from C++ strfry `9acdaeb1f63919184ece5f2dd67af21f1ed62f1b`

The full policy is in [compatibility-policy.md](compatibility-policy.md). This
file tracks concrete differences and inherited behavior still under review;
it is not a promise to reproduce upstream bugs.

## Storage and migration

- strfry LMDB v3 is read only through `wok migrate strfry`. Normal Wok
  commands require a Wok-owned database marker (currently v4).
- Migration preserves exact Event and EventPayload records and checks their
  fingerprint. Wok does not promise that strfry can reopen the result.
- Supported source settings are translated from strfry HOCON into strict Wok
  TOML. Unsupported keys are omitted and external paths require review.
- Wok creates a missing directory for a new Wok database; strfry requires its
  directory to exist.

## Wok extensions

- Wok offers an optional Unix socket transport. Write-policy plugins see
  `sourceType: "unix"` for those connections.
- Wok offers an optional native FIPS datagram transport on Linux, FreeBSD, and
  macOS.
  Write-policy plugins see `sourceType: "fips"` and a peer `npub` key encoded
  as lowercase hex plus its FIPS port. That key is not NIP-42 identity.
- `wok event <levId>` prints one event by local event ID.
- NIP-11 reports Wok's repository as the software implementation.
- Wok implements NIP-50 ranked content search using a Wok-owned derived LMDB
  index. The pinned strfry revision has no NIP-50 implementation.
- Wok returns mergeable NIP-45 HyperLogLog sketches for canonical
  single-target COUNT filters, including address and hashed-string offsets;
  this is not present in the pinned strfry revision.
- Wok serves the NIP-86 management API (ban/allow/block/role methods backed
  by a Wok-owned LMDB moderation table) and NIP-56 report queueing. The
  pinned strfry revision delegates all such decisions to write-policy
  plugins and has no management endpoint.

## Intentional protocol and operational differences

- Ephemeral kinds are live-only by default: after validation, AUTH, and policy
  checks they reach matching active subscriptions without being written to
  LMDB or negentropy. Operators can explicitly select `ttl` compatibility mode,
  and migrated historical ephemeral records continue to age out through cron.
- Wok has native, reloadable abuse controls rather than delegating every
  admission decision to a write-policy plugin: IP/pubkey token buckets,
  pre-scan query costing, historical-query concurrency, author storage quotas,
  and optional NIP-13 proof of work. Migrated configs receive the documented
  Wok defaults and the preflight prints them for review.
- Restricted reads require completed NIP-42 authentication. Wok also delivers
  authenticated state to the negentropy worker and keeps one usable challenge
  per session; the pinned strfry implementation does not complete those paths
  consistently.
- Historical restricted-kind REQ filtering reads PackedEvent from the Event
  table. The pinned strfry request worker attempts to view EventPayload JSON as
  PackedEvent, unlike its live-monitor path.
- JSON input nesting is capped at 128 levels as a denial-of-service bound.
- WebSocket connections have lifecycle timeouts strfry lacks: a pre-upgrade
  HTTP header read deadline (`relay.handshake_timeout_secs`), an idle-gap
  deadline while a partial frame or unfinished fragmented message is
  buffered (`relay.frame_read_timeout_secs`), and ping/pong liveness (a ping
  unanswered for a full `relay.auto_ping_seconds` interval closes the
  connection).
- Mesh client connections do not currently offer permessage-deflate. Wok's
  WebSocket server does negotiate it.

## Compatibility-sensitive behavior retained

- Canonical event serialization rejects duplicate object keys, escapes U+007F,
  and uses the established floating-point formatting. These choices affect
  event ID calculation and migrated stored bytes, so they cannot be casually
  changed.
- The initial Wok v4 database retains the v3 PackedEvent, payload, index, and
  negentropy layouts. This makes the first migration lossless, but is not a
  commitment that later Wok versions retain those internal layouts.

Each correction cites a pinned NIP or a Wok safety requirement and adds a
regression test. Differential parity alone is not a reason to retain it.

## Corrected after adopting this policy

- CLOSED reasons now begin directly with their machine-readable prefix.
- NIP-77 network payload hex rejects `0x` prefixes and half bytes.
- NIP-01 IDs, pubkeys, signatures, and standard `e`/`p` values require the
  specified lowercase hex form.
- Event kinds are limited to 0 through 65535, every tag element must be a
  string, and `a`-tag kind/pubkey parsing follows those same constraints.
- LMDB no longer accidentally enables `MDB_NOMETASYNC` by passing the
  same-valued DBI-only `MDB_CREATE` flag when opening the environment.
- Custom LMDB comparators are total for malformed keys and never panic across
  their C ABI boundary; valid v3/v4 key ordering remains unchanged.
