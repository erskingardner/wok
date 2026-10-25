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
- Wok's filter validation has no `enabled` switch or filter counts of its
  own: each rule applies when set. Migration translates strfry's
  `relay.filterValidation` section to no rules when it is disabled. An
  enabled section keeps its rules, and its `maxFiltersPerReq` lowers
  `relay.max_filters_per_req`, so such a REQ is refused with `arr too big`.
  `minFiltersPerReq` is ignored, and an enabled `maxKindsPerFilter = 0`,
  which strfry applies to refuse every filter that lists kinds, means no
  limit in Wok (migration warns about it); see
  [config.md](config.md#files-from-07-and-earlier).
- Wok creates a missing directory for a new Wok database; strfry requires its
  directory to exist.

## Wok extensions

- Wok offers an optional Unix socket transport. Write-policy plugins see
  `sourceType: "unix"` for those connections.
- `wok event <levId>` prints one event by local event ID.
- NIP-11 `software` is Wok's homepage, `https://github.com/erskingardner/wok`.
- Wok implements NIP-50 ranked content search using a Wok-owned derived LMDB
  index. The pinned strfry revision has no NIP-50 implementation.
- Wok returns mergeable NIP-45 HyperLogLog sketches for canonical
  single-target COUNT filters, including address and hashed-string offsets;
  this is not present in the pinned strfry revision.
- EOSE carries NIP-67 completeness hints (`finish`, `more`, `auth`) when Wok
  knows them; see [nips.md](nips.md). The pinned strfry revision sends a
  two-element EOSE.
- Wok serves the NIP-86 management API (ban/allow/block/role methods backed
  by a Wok-owned LMDB moderation table) and NIP-56 report queueing. The
  pinned strfry revision delegates all such decisions to write-policy
  plugins and has no management endpoint.

## Intentional protocol and operational differences

- `relay.real_ip_header` (strfry's `relay.realIpHeader`) is read as a list:
  Wok takes the last entry across all of the header's lines, the address
  the proxy in front of it wrote, and accepts a port. Pinned strfry parses
  the value as one address, as Wok did through 0.7, so behind a proxy that
  appends to a client's own X-Forwarded-For the client gets the proxy's
  address; in Wok, that let it escape a NIP-86 `blockip`. Wok reads a
  `Forwarded` header as RFC 7239, taking its last element's `for`, which
  strfry cannot parse. When the value names no address both fall back to the
  connecting address; strfry logs every such request, and Wok counts them in
  `wok_real_ip_header_unparsed_total` and warns at most once a minute.

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
  admission decision to a write-policy plugin: per-connection, per-address
  and per-author token buckets,
  pre-scan query costing, historical-query concurrency (excess scans wait
  their turn), author storage quotas,
  and optional NIP-13 proof of work. Migrated configs receive the documented
  Wok defaults and the preflight prints them for review. Per-address buckets
  key an IPv6 client by its /64 (`relay.abuse.ipv6_prefix_len`), so a host
  cannot take a fresh budget from each address in its network; write-policy
  plugins still see the exact address, as in strfry.
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
  buffered (`relay.frame_read_timeout_secs`), a deadline for the whole of
  each message or control frame from its first byte
  (`relay.message_read_timeout_secs`), and ping/pong liveness (a ping
  unanswered for a full `relay.auto_ping_seconds` interval closes the
  connection).
- Mesh client connections do not currently offer permessage-deflate. Wok's
  WebSocket server does negotiate it, and refuses a compressed message that
  inflates past half of `relay.max_websocket_payload_size` plus 64 KiB and
  to more than 32 times its compressed size; strfry inflates any message up
  to its maximum size.
- A WebSocket client that breaks RFC 6455 or RFC 7692 gets a Close frame
  with the status code for the breach before the connection drops: 1002 for
  a framing error, such as a ping, pong, close or continuation frame marked
  compressed (RFC 7692 §6), 1007 for a text message that is not UTF-8 once
  whole and inflated, or a compressed message that does not inflate, and
  1009 for a message too large. The pinned strfry's uWebSockets drops the
  connection with no Close frame, and accepts the compressed bit on control
  and continuation frames once permessage-deflate is negotiated. A binary
  message that is not UTF-8 is still refused with a NOTICE, like any other
  message that is not JSON.
- A client's Close frame is echoed only when its body is valid (RFC 6455
  §5.5.1, §7.4). A 1-byte body, or a status code below 1000, 1004–1006,
  1015, 1016–2999 or 5000 and above, fails the connection with 1002, and a
  reason that is not UTF-8 with 1007. The IANA-registered 1012–1014 and all
  of 3000–3999 are accepted. The pinned strfry's uWebSockets answers any
  invalid Close body with an empty Close frame instead, and counts 1012–3999
  as invalid.
- `wok sync` classifies a peer's negative upload ACK as superseded only when
  its reason starts with `blocked: have a newer version` (Wok's reason) or
  `replaced:` (what strfry and earlier Wok releases send). A foreign peer
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
  drops them; shorter values pack exactly as in v3. Migration keeps v3 records
  byte for byte; `wok reindex` repacks them.
- History order: stored events with the same `created_at` are sent in local
  arrival order, newest arrival first, as in the pinned strfry. NIP-01 says
  the lowest id should come first, and that order also decides which tied
  events a `limit` keeps.
  - No index orders by id. Selecting the lowest ids within the scanner's
    memory, time-slice and resumability bounds proved complex, so this is
    deferred.
  - The options are a capped re-sort of only the tie that a `limit` cuts, or
    an index key that holds the id, in a future storage version.
  - For the same reason, a response is not extended to every event of the
    boundary `created_at`, as NIP-67 says a relay SHOULD. Its `finish` hint is
    sent only when no match is left, so it is never sent for a `limit` cut
    inside a same-second run.

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
  a filter element NIP-01 does not define; negentropy disabled) are NEG-ERR
  with `invalid:`, `unsupported:` or `blocked:` instead of NOTICE, and every
  NEG-ERR closes the session. A NEG-OPEN with an invalid subscription
  id is refused with NEG-ERR too. Only a sub id that is not a string, or a
  NEG-MSG or NEG-CLOSE with an invalid one, still produces a NOTICE.
- NIP-70: a repost (kind 6 or 16) is refused with `blocked: reposts can't
  embed protected events` when its content parses as an event object with a
  tag named `-`. Content that starts as a JSON object but that the strict
  parser refuses is refused too, since clients' parsers accept some of it (a
  repeated key, deep nesting, a lone surrogate, a number too large for a
  double) and could read a protected event there. Pinned strfry refuses any
  repost whose content contains the text `["-"]`, so it refuses reposts of
  notes that only mention it and accepts protected events written with other
  spacing or a tag such as `["-",""]`.
- NIP-01: a subscription id may be any non-empty string of at most 64
  characters, counted in Unicode characters. Every frame JSON-escapes it,
  and subscriptions are keyed by the exact id. Pinned strfry splices the id
  into EVENT frames as it is, so it refuses any id with a control character,
  `"`, `\` or a byte of 0x7F or above, which rules out every non-ASCII id,
  and it counts the 64 in bytes.
- NIP-01: a REQ or COUNT with no filters gets `CLOSED` with
  `invalid: bad req: arr too small`, and like any refused REQ it ends an open
  subscription with its id. Pinned strfry sends only a NOTICE,
  `ERROR: bad req: arr too small`, though NIP-01 says CLOSED MUST be sent
  when a REQ is refused.
- NIP-01: REQ and COUNT refusals that pinned strfry sends as `CLOSED` with
  `error: bad req: ...` keep strfry's text, such as `arr too big`, under the
  NIP-01 prefix that fits. `invalid:` is for malformed filters and requests
  over a size limit, and `unsupported:` for filter elements NIP-01 does not
  define, such as an unknown key or a tag key that is not a single letter
  (NIP-01's own example is `unsupported: filter contains unknown elements`).
  `blocked:` is for `relay.filter_validation` rules, a disabled COUNT and
  Wok's query-work ceiling (`relay.abuse.max_query_work`).
  NIP-01 keeps `error:` "for when none of that fits", so a REQ or COUNT gets
  it only for the relay's own failures, such as a database read that fails.
- OK reasons for storage failures use `error:` instead of `Write error:`, and
  AUTH failures that already carry a NIP-01 prefix are not wrapped in a second
  `error:`. Events refused because free disk space is below
  `database.min_free_disk_bytes` also get `error:`.
- OK reasons for refused events use NIP-01's standardized prefixes. An event
  older than the stored version of its replaceable or addressable event gets
  `blocked: have a newer version`, and one that a deletion or vanish request
  covers gets `blocked: user requested deletion`. The pinned strfry replies
  `replaced: have newer event` and `deleted: user requested deletion`, whose
  prefixes NIP-01 does not define.
- A write-policy plugin's rejection message is sent as is only when it starts
  with a standard NIP-01 prefix. Any other message is sent as
  `blocked: <msg>`, and an empty one as `blocked: rejected by write policy`. A
  `shadowReject` message without a prefix is replaced by the empty reason of
  an accepted event. The pinned strfry sends the plugin's `msg` verbatim, so a
  plugin could produce `false` OKs with an empty or unprefixed reason, which
  NIP-01 forbids.
- NIP-40: an ephemeral event whose `expiration` tag has passed is refused with
  `invalid: event expired` and reaches no subscriber. The pinned strfry packs
  the ephemeral marker in place of the expiration before checking it, so it
  accepted and broadcast such events. `wok sync` and `wok router` downloads
  drop them too. In `ttl` mode a stored ephemeral event
  stays readable until the ephemeral purge even once its expiration passes,
  so `wok sync` counts one it does not transfer, in either direction, as
  `expired` or `upload_expired` instead of failing.
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
- A REQ's filters share one time slice (`relay.query_timeslice_budget_us`).
  Pinned strfry's `DBQuery` restarts the clock for each filter, and carries
  the work count of its last check over to the next filter, which then does
  as much work before it checks again. A REQ of many filters could hold a req
  worker for many slices.
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
  (up to 64); the first identity is the one charged the per-author EVENT
  budget for events the connection publishes from other keys, such as
  Marmot's per-message 445 keys.
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
  their packing, so these limits remain for them until `wok reindex` packs
  them again from their payloads (see `lmdb-v3.md`) and deletes the stored
  versions that a deletion with such a long `a` tag names. The repair keeps a
  record that packs differently in any other way, such as kind 41 history
  packed with a virtual `d`.
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
- NIP-09 `a` tags of replaceable events: a deletion naming
  `<kind>:<pubkey>:`, for kinds 0, 3 and 10000–19999, deletes its author's
  versions up to its `created_at` and refuses such versions that arrive
  later, as for addressable events. The pinned strfry applies `a` tags to
  addressable kinds only, so such a deletion did nothing. Deletion requests
  migrated from strfry or stored by earlier Wok releases take effect when
  `wok reindex` applies them (see
  [lmdb-v3.md](lmdb-v3.md#eventreplacedeletion)).
- NIP-09 `a` tags spelling a kind with leading zeros (`030000:<pubkey>:<d>`)
  are refused with `invalid: a tag kind has leading zeros`, like other
  non-canonical addresses. The pinned strfry reads such a kind as a number,
  so it deletes the stored versions, but tombstones that spelling, which no
  later version is looked up by. Requests stored that way still name the
  canonical address: `wok reindex` deletes the versions that came back and
  tombstones the canonical spelling. An `a` tag longer than 255 bytes is
  held only as the hash of its spelling, so its tombstone stays ineffective.
- NIP-59: kind 21059 ephemeral gift wraps are restricted reads by default,
  alongside kinds 4 and 1059, and NIP-59 is advertised only while both
  gift-wrap kinds are restricted. The previous default let any
  unauthenticated subscriber receive wraps addressed to someone else.
- `created_at` has no lower bound by default, and
  `events.reject_older_than_secs = 0` means none. The pinned strfry defaults
  to three years (`rejectEventsOlderThanSeconds = 94608000`) and treats 0 as
  "now", refusing every event dated in the past. A bound an operator sets
  applies to regular kinds only: replaceable and addressable events,
  deletions (5) and vanish requests (62) are accepted whatever their age.
  NIP-11 omits `created_at_lower_limit` while there is no bound.
- NIP-42: AUTH is accepted within 600 seconds of the relay clock in either
  direction, whatever `[events]` says. The pinned strfry checks AUTH like any
  ephemeral event, within `rejectEphemeralEventsOlderThanSeconds` (60), so a
  client whose clock ran a minute slow could not authenticate. An AUTH event
  that fails validation is refused with `invalid:`, where strfry uses
  `error:`.
- NIP-59: kind 21059 gift wraps may be dated up to three days in the past,
  whatever `reject_ephemeral_older_than_secs` says, because NIP-59
  backdates wraps by up to two days. The pinned strfry refused every such
  wrap older than 60 seconds. In `ttl` mode a wrap older than
  `ephemeral_lifetime_secs` reaches live subscribers, but the next purge
  removes it, so history does not serve it.
- NIP-78: kinds 78 and 30078 are owner-only by default
  (`relay.auth.owner_only_kinds`). They are served only to a connection
  authenticated as their author, and accepted only from one: without AUTH an
  EVENT gets `auth-required:` and a challenge, and on a connection
  authenticated as another key, `restricted:`. NIP-78 says both SHOULD hold
  for this private app data. The pinned strfry serves and accepts them like
  any kind.
- `relay.auth.restricted_read_kinds` and `restrict_read_to_involved_pubkey`
  are replaced by read classes: `recipient_only_kinds` (author and first
  `p`-tag recipient), `owner_only_kinds` and `authenticated_kinds`. strfry's
  `restrictReadToInvolvedPubkey = false` skipped the per-event check, so a
  REQ that mixed in an unrestricted kind returned the restricted kinds without
  AUTH. Wok has no such mode: a file or strfry config that sets it gets its
  kinds as `authenticated_kinds`, readable after AUTH as any key and never
  without. While AUTH is unusable, events of recipient-only and
  authenticated kinds are refused with `restricted:`, since nobody could
  read them; strfry stores them.
- `relay.auth.write_policy` and `read_policy` (`open`, `authenticated` or
  `members`) replace `restrict_writes`, which the pinned strfry does not
  have. Under `write_policy = "members"` an event is accepted when its author,
  a pubkey its connection authenticated as, or, for `inbox_kinds`, its first
  `p`-tag recipient is a member, so members' Marmot group messages and gift
  wraps from throwaway keys are accepted (#97 C7).
- `[relay.filter_validation]` applies to NEG-OPEN as well as REQ and COUNT,
  so a sync cannot list the ids a REQ may not ask for. The pinned strfry
  validates REQ and COUNT filters only. NEG-OPEN filters also meet
  `relay.max_req_filter_size` and, per connection,
  `relay.max_filter_bytes_per_connection`. `require_scoped_filters`, which Wok
  adds, needs each filter to name `ids`, `authors` or a tag.
- NIP-42: kind 22242 events reach no client. One sent as EVENT is refused
  with `invalid: AUTH events must be sent with AUTH`. `wok import` refuses
  one, as do `wok sync` and `wok router` downloads, in either ephemeral mode.
  `wok migrate strfry` and `wok reindex` keep stored records unchanged. Such
  a record, or one committed by another writer, is hidden from REQ, COUNT,
  live delivery, NIP-77 and router/sync uploads until the ephemeral purge
  removes it. Operator tools still reach it: `wok scan` finds it and
  `wok delete --filter '{"kinds":[22242]}'` removes it, even offline. The
  pinned strfry treats kind 22242 like any ephemeral event: it stores it and
  delivers it to matching subscriptions, which NIP-42 forbids.
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
- NIP-01 single endpoint: only `/` accepts WebSocket upgrades and serves
  NIP-11, NIP-86 and the landing page. Other paths return 404, apart from
  `/admin` and, when they are on, the NodeInfo routes and `/metrics`. NodeInfo
  is off unless `relay.nodeinfo_enabled` is set; the pinned strfry always
  serves it. The pinned strfry upgrades and serves NIP-11 on every path, so
  one relay answers under many URLs. A reverse proxy that serves the relay
  under a path prefix must strip it.
- NIP-11 CORS: relay responses send `Access-Control-Allow-Origin`,
  `-Allow-Headers` and `-Allow-Methods`, and `OPTIONS /` is a 204 preflight
  reply. NIP-11 is chosen when `Accept` lists `application/nostr+json` among
  other media ranges with a nonzero `q`. The pinned strfry sends only
  `Access-Control-Allow-Origin`, answers OPTIONS with the landing page, and
  serves NIP-11 only when `Accept` is exactly `application/nostr+json`.
