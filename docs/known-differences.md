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

- Canonical stored event serialization rejects duplicate object keys, escapes
  U+007F, and uses the established floating-point formatting. These choices
  affect migrated stored bytes, so they cannot be casually changed.
- The initial Wok v4 database retains the v3 PackedEvent, payload, index, and
  negentropy layouts. This makes the first migration lossless, but is not a
  commitment that later Wok versions retain those internal layouts. Wok now
  also packs single-letter tag values longer than 255 bytes, by hash, where v3
  drops them; shorter values pack exactly as in v3.

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
- A validated EVENT is committed even when its connection closes before the
  writer reaches it; only the OK is lost. The pinned strfry writer drops events
  whose connection closed within the same write batch, which lost posts from
  clients that publish and hang up at once. An EVENT still parked in an
  ingester because the writer queue is full is dropped when its connection
  closes, which keeps memory bounded under writer backpressure.
- NIP-01 tag filters and addresses: single-letter tag values longer than 255
  bytes are packed and indexed as a marker byte and their SHA-256, so `#x`
  filters match them, an addressable event whose first `d` tag is that long
  has its own address, and a kind 5 `a` tag that long deletes and tombstones
  its target. An addressable event whose `a` tag would exceed
  `events.max_tag_val_size` is refused with `invalid:`, so every stored
  address can be named by an `a` tag. The pinned strfry drops such values: it keys that event by its
  virtual empty `d` (or a later short `d`), so distinct addresses replace one
  another, never matches that deletion against its target, and refuses such
  filters. Records migrated from strfry or stored by earlier Wok releases keep
  their packing, so these limits remain for them (see `lmdb-v3.md`).
- NIP-01 kind ranges: kind 41 (NIP-28 channel metadata) is regular. The pinned
  strfry treats it as replaceable per author, so metadata for a second channel
  deleted the first channel's. Migrated kind 41 history stays stored and
  becomes visible, and the superseded-version count is redone on the first
  writable open (see [lmdb-v3.md](lmdb-v3.md)).
- NIP-09: a deletion request against a deletion request has no effect. A kind
  5 `e` tag never deletes a stored kind 5, and an earlier tombstone does not
  block a kind 5 from being stored. The pinned strfry exempts neither, so
  deleting a deletion removed it with its tombstone and the original event
  could be published again.
- NIP-59: kind 21059 ephemeral gift wraps are restricted reads by default,
  alongside kinds 4 and 1059, and NIP-59 is advertised only while both
  gift-wrap kinds are restricted. The previous default let any
  unauthenticated subscriber receive wraps addressed to someone else.
- NIP-42: kind 22242 events reach no client. One sent as EVENT is refused
  with `invalid: AUTH events must be sent with AUTH`. `wok import` refuses
  one, as do `wok sync` and `wok router` downloads, in either ephemeral mode.
  `wok migrate strfry` and `wok reindex` keep stored records unchanged. Such
  a record, or one committed by another writer, is hidden from REQ, COUNT,
  live delivery, NIP-77 and router/sync uploads until the ephemeral purge
  removes it. The pinned strfry treats kind 22242 like any ephemeral event:
  it stores it and delivers it to matching subscriptions, which NIP-42
  forbids.
- NIP-01 event ids are hashed over the NIP-01 preimage, which includes U+007F
  verbatim like go-nostr, nostr-tools and serde_json. strfry's tao serializer
  escapes it as `\u007f`, so a correctly signed event containing DEL was
  refused with `invalid: bad event id`. Stored payloads keep tao escaping, which
  is valid JSON for the same string. A published EVENT, AUTH or NIP-98 event
  must use the NIP-01 id. `wok import` (with verification), `wok sync` and
  `wok router` downloads also accept the legacy tao preimage, because strfry
  and earlier Wok releases stored events under it. Accepting both cannot give
  two different events one id: the preimages agree unless the event contains
  DEL, and then the NIP-01 preimage has a raw DEL byte that a tao preimage
  never has. Integrity checks, `wok migrate strfry` and `wok doctor` never
  rehash ids, so migrated data is unaffected. A Wok relay refuses legacy-id
  events that `wok sync` uploads to it, because uploads are EVENTs.
