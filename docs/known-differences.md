# Known differences from C++ strfry `9acdaeb1f63919184ece5f2dd67af21f1ed62f1b`

The full policy is in [compatibility-policy.md](compatibility-policy.md). This
file tracks concrete differences and inherited behavior still under review;
it is not a promise to reproduce upstream bugs.

## Storage and migration

- strfry LMDB v3 is read only through `wok migrate strfry`. Normal Wok
  commands require a Wok-owned database marker (currently v5).
- Migration preserves exact Event and EventPayload records and checks their
  fingerprint. Wok does not promise that strfry can reopen the result.
- Supported source settings are translated from strfry HOCON into strict Wok
  TOML. Unsupported keys are omitted and external paths require review.
- Wok creates a missing directory for a new Wok database; strfry requires its
  directory to exist.

## Wok extensions

- Wok offers an optional Unix socket transport. Write-policy plugins see
  `sourceType: "unix"` for those connections.
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

- Latest-only replaceable reads are enforced independently of physical
  cleanup. Retained source versions cannot reappear through historical REQ,
  COUNT, search, live catch-up, or NIP-77. This follows pinned NIP-01 and is
  covered by `wok-compat/tests/replaceable_events.rs`.
- Replacement writes and address deletions handle every retained version at an
  address; the pinned strfry writer inspects only one replacement-index entry.
  Rejected writes do not apply proposed physical cleanup.
- Ephemeral kinds are live-only by default: after validation, AUTH, and policy
  checks they reach matching active subscriptions without being written to
  LMDB or negentropy. Operators can explicitly select `ttl` compatibility mode,
  and migrated historical ephemeral records continue to age out through cron.
- A REQ is registered with the live monitor before its history is scanned
  (see [architecture.md](architecture.md#req-lifecycle)). Pinned strfry
  installs the live filter only after the history and catches up from the
  database, which works there because it stores ephemeral events for five
  minutes. Wok's live-only ephemeral events cannot be caught up, so they were
  lost while the history was being sent.
  - The history covers what was stored when the REQ was admitted. Anything
    stored later is delivered live, even when the filter's `limit` (such as
    `limit: 0`) keeps it out of the history. In pinned strfry the boundary is
    when the req worker starts the scan, so an event committed between the
    REQ's arrival and that point is history and can be cut by `limit`.
  - Everything that arrives while the history is sent follows EOSE, as NIP-01
    defines EOSE as the boundary to "events newly received in real-time".
    Pinned strfry sends stored events committed during the scan before EOSE.
    Clients treat events after EOSE as new, and the stream before EOSE stays
    strictly newest-first. The cost: a fetch-and-close client that sends
    CLOSE at EOSE does not get events that arrived during the scan.
  - The held matches are bounded per subscription
    (`relay.max_live_buffer_bytes`). Past the bound, stored events are re-read
    from the database and the oldest ephemeral events are dropped and counted.
  - No req worker waits on a monitor. Pinned strfry's worker blocks on the
    monitor for every REQ before sending EOSE.
- Wok has native, reloadable abuse controls rather than delegating every
  admission decision to a write-policy plugin: IP/pubkey token buckets,
  pre-scan query costing, historical-query concurrency, author storage quotas,
  and optional NIP-13 proof of work. Migrated configs receive the documented
  Wok defaults and the preflight prints them for review.
- Restricted reads require completed NIP-42 authentication. Wok also delivers
  authenticated state to the negentropy worker and keeps one usable challenge
  per session; the pinned strfry implementation does not complete those paths
  consistently.
- Restricted-kind events are always visible to their authenticated author.
  The pinned strfry hides restricted events that have no `p` tag from
  everyone, including the author.
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
- `wok sync` classifies a peer's negative upload ACK as superseded only when
  its reason starts with `replaced:` (the prefix used by Wok). A foreign peer
  using different wording is counted as `upload_rejected`, and the run exits
  nonzero even if replacement semantics explain the difference. Arbitrary
  human-readable rejection text is not treated as evidence of supersession.

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
- NIP-42: `auth-required:` and an AUTH challenge are sent only while
  authenticating can change the outcome. When AUTH is unusable (auth disabled
  or no `service_url`), restricted REQ, COUNT, and NEG-OPEN get a final
  `restricted:` with no challenge, and AUTH itself is refused with `blocked:`;
  pinned strfry still challenges and then rejects every AUTH. An authenticated
  COUNT that is not scoped to an authenticated key is `restricted:`, not
  another `auth-required:`. `relay.auth.enabled = false` now also refuses AUTH.
- NIP-42: while AUTH is usable, the challenge is sent when the connection
  opens, not only after a restricted request is refused. A client can then
  authenticate before its first REQ, so a restricted live subscription such
  as a NIP-46 kind-24133 response feed does not miss ephemeral replies while
  it is refused, authenticated, and re-sent.
- NIP-77: NEG-OPEN and NEG-MSG refusals (malformed envelope, hex, or filter;
  negentropy disabled) are NEG-ERR with `invalid:` or `blocked:` instead of NOTICE, and
  every NEG-ERR closes the session. Only an unusable subscription id still
  produces a NOTICE.
- OK reasons for storage failures use `error:` instead of `Write error:`, and
  AUTH failures that already carry a NIP-01 prefix are not wrapped in a second
  `error:`.
- NIP-01: a REQ over `relay.max_subs_per_connection` is refused with
  `CLOSED` (`blocked: too many concurrent REQs`) before its history is sent.
  Pinned strfry sends the history, EOSE, and then a NOTICE, and the
  subscription is never live.
- NIP-01: a REQ that reuses an open subscription id replaces it even when the
  REQ is refused. The old subscription stops at once, and the refusal's CLOSED
  follows its last EVENT. In pinned strfry a refused REQ leaves the old live
  filter running, so `CLOSED x` is followed by more `EVENT x`, and an accepted
  one keeps the old filter live until the new history finishes.
- COUNT and REQ ids are separate. In pinned strfry a COUNT that reuses an
  in-flight REQ's id cancels the REQ's history scan, which then never sends
  EOSE. CLOSE ends only the REQ.
- NIP-77 network payload hex rejects `0x` prefixes and half bytes.
- NIP-01 IDs, pubkeys, signatures, and standard `e`/`p` values require the
  specified lowercase hex form.
- Event kinds are limited to 0 through 65535, every tag element must be a
  string, and `a`-tag kind/pubkey parsing follows those same constraints.
- LMDB no longer accidentally enables `MDB_NOMETASYNC` by passing the
  same-valued DBI-only `MDB_CREATE` flag when opening the environment.
- Custom LMDB comparators are total for malformed keys and never panic across
  their C ABI boundary; valid v3/v4/v5 key ordering remains unchanged.

- Wok v5 adds transactional author counters and a monotonic local event
  sequence in `wok_State`. Opening a v4 database for normal Wok writes upgrades
  its marker atomically; signed records and payloads are not rewritten. Counters
  initialize per author on first mutation. Older Wok writers refuse v5.
- All read paths, including COUNT/HLL and NIP-77 ID reconciliation, enforce
  the same first-recipient/author policy, moderation, vanish and expiry checks.
  Multiple successfully authenticated identities remain valid on one connection
  (up to 64); the first identity remains the connection's rate-limit identity.
