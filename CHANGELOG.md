# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Update Rustls to 0.23.46 for RUSTSEC-2026-0346, -0347, -0348 and -0349
  (client session secrets in `Debug` output, data sent after an ECH rejection,
  unbounded Brotli certificate decompression, and a key-exchange downgrade).
  As before, only the CLI's outbound clients and the benchmark harness use
  Rustls.
- Update Rustls to 0.23.45 for RUSTSEC-2026-0285 (TLS 1.3 handshake messages
  accepted across encryption-level boundaries). Rustls is used only by the
  CLI's outbound `wss://` and HTTPS clients (mesh, router, upload/download,
  NIP-11 fetches) and the benchmark harness; the relay listener does not
  terminate TLS.
- NIP-62 vanish requests (kind 62) now pay NIP-13 proof of work and the
  per-author EVENT budget like any other event. Before, a validly signed vanish
  request skipped both and only the per-address budget limited them. They
  still bypass the write-policy plugin, now documented: NIP-62 requires relays
  that restrict who can post to honor vanish regardless of the user's status
  (#48).
- NIP-62 vanish requests are now honored from banned authors and, with
  `relay.auth.restrict_writes`, from pubkeys not on the write allowlist. Before,
  both were refused, so an author who lost write access could not erase what
  they had published, contrary to NIP-62's requirement that relays which
  restrict who can post honor vanish regardless of the user's status. Event-id
  bans, the kind allowlist and `relay.nip62.enabled` still apply.
- A signed NIP-98 authorization can no longer run two admin API or NIP-86
  requests at once. Its replay-cache ID was burned only after the request
  succeeded, so concurrent requests reusing one captured header all passed the
  check and executed. The ID is now reserved when the request is authorized.
  It is released only when the request failed without effect, so those can
  still be retried; a NIP-86 command that reached the writer keeps it burned
  even if the client disconnects (#51).
- Malformed client messages now draw on a per-address token bucket
  (`relay.abuse.invalid_rate_per_second`, default 5, and `invalid_burst`,
  default 20). Before, every one earned a NOTICE, so one connection could make
  the relay answer garbage without limit. Once the budget is spent the client
  gets one `rate-limited` NOTICE and further malformed messages are ignored
  until it refills; rejections count as `invalid_rate`. Only the reply is
  suppressed: valid CLOSE and NEG-CLOSE are never budgeted, and a malformed
  NEG-OPEN/NEG-MSG that names a session still closes it (#49).
- A busy query or sync worker can no longer stall unrelated connections. Before,
  an ingester blocked when a worker's queue was full, which held up every
  connection sharing that ingester, including their CLOSE and disconnect
  cleanup. Ingesters now park work for a full worker in order and retry it
  without blocking. A connection with parked work has its new messages held
  until that work moves, but keeps receiving events, answering pings and
  noticing Close and disconnects; a client that keeps sending past the hold
  (its maximum message size) is disconnected. Connections that do not use the
  busy worker keep going. A disconnect drops that connection's parked and held
  work (REQs, CLOSEs, sync messages and unwritten events) instead of running it,
  and frees its subscriptions, sync sessions and memory reservations.
- Three settings documented as live now take effect on reload instead of
  keeping their startup value until restart: `relay.write_policy_timeout_secs`
  (the write-policy plugin's deadline), `relay.max_subs_per_connection`, and
  the COUNT dedup budget derived from `relay.max_filter_limit_count`. An
  operator who shortened the plugin timeout to contain a hanging plugin was
  still waiting the old duration (#54).
- Ephemeral gift wraps (kind 21059) are restricted reads by default:
  `relay.auth.restricted_read_kinds` now defaults to `[4, 1059, 21059]`.
  Before, any unauthenticated subscription to kind 21059, or to everything,
  received wraps addressed to someone else, recipient tag included, while
  NIP-59 was advertised. NIP-59 is now advertised only while both gift-wrap
  kinds are restricted; configs that list restricted kinds explicitly need
  21059 added.

### Added

- Configuration presets. The optional top-level key `preset` selects a named
  set of defaults; configuration resolves as built-in defaults, then the
  preset's overlay, then the file. `public`, the built-in defaults, is the
  only preset and is selected when the key is absent, so no default changes.
  Unknown preset names are rejected. `wok config show` prints the effective
  configuration with each value's origin (default, preset, or file and line),
  and `--overrides` prints only the keys the file changes from its preset.
  Files written by dashboard saves and `wok migrate strfry` now include
  `preset = "public"`.
- `wok-bench --scenario clients` measures default limits the way clients hit
  them. Abuse controls and AUTH stay on, or the scenario runs a supplied relay
  TOML (`--relay-config`). It simulates outbox clients with about 30
  subscriptions each and MDK-shaped Marmot clients: AUTHed inboxes, per-group
  NIP-77 passes, directory batches and add-member bursts. It reports time to
  first EVENT and to EOSE per subscription class, and counts refusals by
  reason. It measures the default changes planned in #97.
- `relay.max_live_buffer_bytes` (default 262144) bounds the live matches held
  for one subscription while its history is sent. Past it, stored events are
  re-read from the database after EOSE and the oldest ephemeral events are
  dropped. The new counters `wok_live_buffer_overflows_total` and
  `wok_live_buffer_dropped_ephemeral_total` show when that happens.
- `wok purge-superseded` deletes older versions of replaceable and addressable
  events retained by a strfry migration or written before 0.7.0, keeping the
  version relay reads serve. `--dry-run` reports counts without changing the
  database, and `--json` prints a summary. It runs alongside the relay in
  bounded write transactions. Doctor's `replacement-history` warning points to
  it.
- `wok reindex` restores single-letter tag values longer than 255 bytes to
  records that strfry or earlier Wok releases packed without them, so `#x`
  filters match those values, a long first `d` becomes the record's own
  address, and a long deletion `a` tag tombstones its address. While it builds
  the staged database it packs each such record again from its payload, and
  copies it unchanged unless the only difference is the restored values; kind
  41 history packed with a virtual `d` is copied unchanged. Indexes, the
  superseded-version count and negentropy trees are rebuilt from the result.
  Reindex then verifies the fingerprint without hashed tag values (the full
  fingerprint when nothing was repacked). Its outcome and manifest report
  `repacked_long_tag_records`, `skipped_long_tag_records` and the original's
  fingerprint as `source_event_fingerprint_sha256`. Integrity reports
  `legacy_long_tag_records`, doctor warns while it is nonzero, and the
  migration manifest records it. Migration still copies records unchanged.
- `wok reindex` applies the deletions its long-tag repair restores. Each
  stored deletion request with an `a` tag longer than 255 bytes deletes the
  versions of the address it names, by its author, up to its `created_at`, as
  the relay does when such a request arrives (NIP-09). strfry and earlier
  releases left those versions stored and visible. The request and newer
  versions stay. The outcome and manifest count the deleted versions as
  `deleted_under_repaired_deletions`, the original database in the backup
  keeps them, and verification compares the result with the original's
  fingerprint without them.

- NIP-86 `unbanevent`, `unallowevent`, `listallowedevents` and
  `listdisallowedkinds`, from the current NIP-86 draft. `allowevent` also
  puts the event on an allow list, with its optional reason, which
  `listallowedevents` returns; the allow list records the approval and
  changes no visibility. The NIP-43 claim methods are not implemented.

### Preset changes

- `public`: `events.reject_older_than_secs` is `0`, no lower bound on
  `created_at` (was 94608000, three years), and NIP-11 omits
  `created_at_lower_limit`. A 2020 profile, follow list or deletion can be
  rebroadcast again. Files that pin the old value, as copies of the 0.7
  `docs/wok.toml` do, keep the bound, but it now spares the kinds listed
  under Changed.

### Changed

- A bound set with `events.reject_older_than_secs` applies to regular kinds
  only. Replaceable (0, 3, 10000–19999) and addressable (30000–39999) events
  and deletions (5) are now accepted whatever their age, like vanish requests
  (62) already were.
- AUTH events that fail validation (id, signature, timestamp window or NIP-40
  expiration) are refused with `invalid:`, as they would be if sent as
  EVENT, instead of `error:`.
- Events that arrive while a REQ's history is being sent now come after EOSE,
  as NIP-01's "newly received in real-time" events, and the stream before
  EOSE stays newest-first. Before, stored events committed during the scan came
  before EOSE, as in strfry. A client that sends CLOSE at EOSE no longer gets
  them.
- Frames for different connections are queued under per-connection locks
  instead of one relay-wide lock, so live fan-out to many connections no
  longer serializes on it.
- A REQ queued behind CLOSEs, AUTH or disconnects no longer waits a query time
  slice for each of them while other queries run. The req worker now takes
  everything queued in one pass, and starts each new REQ or COUNT as it takes
  it. Running queries still get a slice every pass.

### Removed

- Dated benchmark, soak, lab and audit reports, the definition-of-done report
  and `PLAN.md` are no longer kept in the repository or shipped in release
  archives. `docs/` now holds only design, policy, operations and benchmark
  methodology; results belong in pull requests.

### Fixed

- `events.reject_older_than_secs = 0` refused every event dated in the past.
  It now means no lower bound.
- AUTH used the 60-second window for ephemeral events, so a client whose
  clock ran two minutes slow could not authenticate (`error: ephemeral event
  expired`). AUTH is now accepted within 600 seconds of the relay clock in
  either direction, as NIP-42 suggests, whatever `[events]` says.
- Kind 21059 ephemeral gift wraps dated more than 60 seconds in the past were
  refused, which was every wrap backdated as NIP-59 recommends. They may now
  be dated up to three days in the past.
- Ephemeral events published while a REQ's history was being sent were lost.
  The live filter was installed only after the history, and live-only events
  are never stored, so nothing could catch them up: NIP-46 replies and
  ephemeral gift wraps sent during a slow scan never arrived. A REQ is now live
  before its history scan starts, so every event published after it arrives,
  exactly once. Stored events published after the REQ arrive even when its
  `limit`, such as `limit: 0`, keeps them out of the history.
- A REQ that reuses a subscription id now stops the old filter at once, even
  when the new REQ is refused. Before, the old filter kept delivering until the
  new history finished, and forever after a refused REQ, so `CLOSED x` was
  followed by more `EVENT x`.
- Events and EOSE already queued for a subscription that was then replaced or
  closed are dropped instead of sent. On a slow link, a client that replaced a
  subscription could otherwise receive the old filter's backlog after the new
  REQ.
- A REQ over `relay.max_subs_per_connection` gets `CLOSED` (`blocked: too many
  concurrent REQs`) and no EOSE. Before, it got its history, an EOSE and a
  NOTICE, and never went live.
- A COUNT no longer cancels an in-flight REQ with the same id, which then never
  sent EOSE. COUNT and REQ ids are separate, and CLOSE ends only the REQ.
- A busy req monitor no longer holds up every REQ behind it: the req worker
  sends no EOSE itself and never waits for the monitor. Gone with it is the
  5-second wait that could end in a "live subscription monitor unavailable"
  NOTICE and an EOSE for a subscription that never went live.
- The relay could crash with a segmentation fault while shutting down. LMDB
  clears a thread's reader slot from a thread-local destructor as the thread
  exits, and the database was closed by whichever relay thread exited last,
  so it could unmap the slot under another thread's destructor. The three
  req monitors exit together, which made this reachable: about one in a
  thousand runs of a test that starts and stops six relays crashed on Linux.
  The database now closes only after every relay thread has exited.
- `wok reindex` rebuilt negentropy trees from what relay reads serve, so a
  database with superseded versions (retained by a strfry migration, or created
  when reindex repacks a long address next to a newer version) came out with
  trees that `wok doctor` reported as inconsistent with the primary records.
  Trees now hold every stored record their filter matches, as the writer and
  `wok negentropy build` keep them; syncs still apply read visibility.
- While NIP-42 is usable, the AUTH challenge is sent as soon as a connection
  opens instead of only after a restricted request is refused. NIP-46 clients
  such as Bunker46 can authenticate before subscribing to restricted kind
  24133, so the bunker's ephemeral replies are no longer lost while the
  client re-subscribes (#64).
- Restricted reads no longer ask for AUTH that cannot succeed. Without a usable
  NIP-42 setup (auth disabled or no `service_url`), REQ, COUNT, and NEG-OPEN
  for restricted kinds are refused with `restricted:` and no challenge, and
  AUTH replies `blocked:`. `relay.auth.enabled = false` now actually refuses
  AUTH. An authenticated COUNT that is not scoped to the authenticated key gets
  `restricted:` instead of a repeated `auth-required:`.
- NIP-77 refusals that name a subscription (malformed envelope, hex, or filter;
  negentropy disabled) are NEG-ERR with `invalid:` or `blocked:` instead of NOTICE, so sync
  clients stop waiting. Every NEG-ERR, including rate limits, now closes the
  session on the relay as NIP-77 specifies.
- OK reasons for storage failures start with `error:` instead of
  `Write error:`, and prefixed AUTH failures are no longer double-prefixed.
- `relay.bind` accepts bare IPv6 literals (`::1`) and hostnames. A hostname
  binds every address it resolves to, so `localhost` listens on both
  `127.0.0.1` and `::1`; resolved addresses this host cannot use are skipped
  with a warning. Bind failures now stop startup instead of leaving the
  relay running without a WebSocket listener.
- Authors can read their own restricted-kind events that have no `p` tag
  (for example NIP-78 kind 30078 app data). Before, REQ, COUNT, live
  delivery, and sync hid them from everyone, including the author.
- AUTH is rate-limited and no longer verifies signatures for connections that
  were never sent a challenge. It draws on the per-address EVENT budget and
  replies `rate-limited: AUTH budget exhausted` once that runs out, so a few
  connections can no longer tie up every ingester thread with signature checks.
- Events are stored even when the publisher disconnects right after sending
  them. The writer dropped every EVENT whose connection closed within the same
  write batch, so bots, CLI tools and mobile apps that publish and hang up lost
  posts (of eight such publishers, one event was stored). Only the OK is lost
  now. An EVENT still parked behind a full writer queue is dropped when its
  connection closes, as before.
- Single-letter tag values longer than 255 bytes are indexed by their SHA-256.
  They were not indexed at all, so an addressable event whose first `d` tag
  was that long was keyed by an empty `d` and distinct addresses replaced one
  another (`d=""`, a 300-byte `d` and a 301-byte `d`), a kind 5 `a` tag that
  long never deleted its target, and `#x` filters for such values were
  refused. An addressable event is refused with `invalid:` when the `a` tag
  naming it would exceed `events.max_tag_val_size`, so every stored address
  can still be deleted by `a` tag. Events stored by earlier releases or
  migrated from strfry keep their packing, so filters cannot match their long
  values until `wok reindex` repacks them.
- Kind 41 (NIP-28 channel metadata) is a regular event, as NIP-01 makes every
  kind from 4 to 44. It was replaced per author, so metadata for a second
  channel deleted the first channel's. Migrated kind 41 history becomes
  visible, and the superseded-version count is redone once on the next
  writable open (state key `superseded-versions` replaces `superseded-events`).
- A deletion request against a deletion request has no effect, as NIP-09
  requires. Before, a kind 5 deleting an earlier kind 5 removed it with its
  tombstone, and the originally deleted event could be published again.
- A deletion's `a` tag naming a replaceable event, `<kind>:<pubkey>:` for
  kinds 0, 3 and 10000–19999, deletes that author's versions up to the
  request's `created_at` and refuses such versions published later, as NIP-09
  asks and as for addressable events. Such deletions did nothing. Deletion
  requests already stored, including those migrated from strfry, take effect
  when `wok reindex` applies them; until then `wok doctor` warns
  (`deletion-tombstones`).
- A deletion `a` tag whose kind has leading zeros (`030000:<pubkey>:<d>`) is
  refused with `invalid: a tag kind has leading zeros`, as are such lines in
  `wok import` (fried included) and such events in `wok sync` and `wok router`
  downloads. It deleted the stored versions of the address, but its tombstone
  never refused later ones. Such
  requests stored by strfry or earlier releases still name the canonical
  address: `wok reindex` deletes the versions that came back and tombstones
  the canonical spelling, except for an `a` tag longer than 255 bytes.
- A kind 22242 AUTH event sent with EVENT is refused with
  `invalid: AUTH events must be sent with AUTH`. It was accepted and delivered
  to matching subscriptions (and stored in `ttl` mode), which NIP-42 forbids.
- `wok import`, `wok sync` and `wok router` no longer store kind 22242 AUTH
  events; import and sync count them as rejected. They stored them in either
  ephemeral mode, and the relay then delivered them to live subscriptions. A
  22242 already in the database, from strfry or another writer, is now hidden
  from REQ, COUNT, live delivery and NIP-77 sync.
- Event ids are checked against the NIP-01 preimage, which includes U+007F
  (DEL) verbatim. Events with DEL in a tag or content, signed by go-nostr,
  nostr-tools or anything built on serde_json, were refused with
  `invalid: bad event id` because Wok, like strfry, escaped it as `\u007f`.
  Stored payloads keep that escaping. `wok import`, `wok sync` and
  `wok router` downloads also accept the legacy id, so data from strfry and
  earlier Wok releases still verifies.
- NIP-86 ban and allow lists replace each other, as NIP-86 asks:
  `banpubkey` and `banevent` take the pubkey or event off the allow list,
  and `allowpubkey` and `allowevent` lift its ban. A pubkey could be on both
  lists, and the ban won. A pubkey that an earlier release left on both lists
  stays there, with the ban still winning, until the next `banpubkey` or
  `allowpubkey` for it; `unbanpubkey` alone leaves it allowlisted.
- NIP-86 `supportedmethods` lists only the methods the caller may call, so
  moderators no longer see the admin-only ones.
- NIP-86 `listallowedkinds` lists the kinds named by `allowkind` since their
  last `disallowkind`. It listed every allowed kind: all 65,536 with no kind
  policy, and 65,535 after one `disallowkind`. `listdisallowedkinds` lists
  the disallowed kinds. Which kinds are accepted does not change.
- The relay is served on a single endpoint, as NIP-01 requires. Only `/`
  accepts WebSocket upgrades and serves NIP-11, NIP-86 and the landing page;
  other paths return 404, apart from `/admin`, `/metrics` and the nodeinfo
  routes. Before, every path upgraded and served NIP-11, so one relay
  answered under any number of URLs. A reverse proxy that serves the relay
  under a path prefix must now strip the prefix.
- Relay HTTP responses send `Access-Control-Allow-Headers` (`Content-Type,
  Authorization, Accept`) and `Access-Control-Allow-Methods` (`GET, POST,
  OPTIONS`) as well as `Access-Control-Allow-Origin`, as NIP-11 requires, and
  `OPTIONS /` answers a CORS preflight with 204 instead of the landing page.
  NIP-86 replies carry them too, so browser management tools can call the
  API. The admin dashboard API stays same-origin.
- NIP-11 is served whenever the `Accept` header lists
  `application/nostr+json`, for example
  `application/nostr+json, application/json;q=0.9`. Only that exact header
  value was recognized, and anything else got the landing page. Both
  documents at `/` now send `Vary: Accept`, so caches keep them apart.
- NIP-11 `software` is the homepage URL `https://github.com/erskingardner/wok`,
  as NIP-11 requires. It was the git remote
  `git+https://github.com/erskingardner/wok.git`.
- Refused events get OK reasons with NIP-01's standard prefixes. An event
  older than the stored version of its replaceable or addressable event gets
  `blocked: have a newer version` (was `replaced: have newer event`), and a
  deleted one `blocked: user requested deletion` (was `deleted:`). `wok sync`
  counts an upload refused with either the new or the old superseded reason as
  `upload_superseded`, so peers running strfry or earlier Wok releases are
  still recognized.
- A write-policy plugin that rejects an event with an empty or unprefixed
  `msg` no longer produces an OK reason without a NIP-01 prefix: the client
  gets `blocked: <msg>`, or `blocked: rejected by write policy` for an empty
  one. Messages that already start with a standard prefix are unchanged. A
  `shadowReject` with an unprefixed `msg` now sends an empty reason, like an
  accepted event.
- An ephemeral event published with an `expiration` tag in the past is refused
  with `invalid: event expired`, as NIP-40 asks. It was accepted and sent to
  matching live subscriptions, because the ephemeral marker replaced the
  expiration before it was checked. `wok sync` and `wok router` downloads drop
  such events too. `wok sync` neither uploads nor fails on one that a `ttl`-mode
  database still holds; its summary counts them as `expired` and
  `upload_expired`.
- Events refused because free disk space is below
  `database.min_free_disk_bytes` get `error: disk reserve requires N free
  bytes` instead of `blocked:`. A low disk is the relay's own failure, not a
  policy decision about the event or its author.

## [0.7.0] - 2026-09-08

### Fixed

- Empty CLI sync filters return a structured error instead of panicking. Router
  forwarding honors the configured ephemeral-event lifetime. Integrity avoids
  misleading replacement-counter drift reports when indexes are already corrupt.
- New winning replacements remove every older version at their address in one
  transaction, including quota and negentropy updates. Stale writes compare
  against all stored versions, and address deletions remove all eligible history.
- Doctor and migration report retained superseded groups/events without changing
  lossless migration records. Sync and router uploads suppress stale versions;
  sync reports superseded transfers separately from failures and bounds filtered
  view construction using the configured sync event/memory budgets.
- Historical queries, COUNT, search, live delivery, and NIP-77 suppress older
  replaceable events even when a lossless import retained multiple versions.
  Contact lists (kind 3), other replaceable kinds, and addressable events share
  timestamp/ID winner selection independent of query filters. Physical records
  remain intact. A transactional retained-history count preserves persistent
  negentropy trees for clean databases; filters that may include superseded
  records use the bounded filtered view.
  Databases retaining history therefore cannot perform replaceable-inclusive
  reconciliation above `relay.max_sync_events` (default 1,000,000) or the memory
  budget until history is removed or the filter is narrowed. A dedicated purge
  command remains follow-up work.

## [0.6.1] - 2026-09-07

### Fixed

- CLI import and delete update negentropy trees atomically with primary records.
  Doctor verifies exact tree membership against primary events and reports existing
  drift; sync verifies matching local trees before using them. Import exits nonzero
  when any records are rejected. Router reports CLOSED subscription messages.
- Missing-ID comparison terminates when sets differ. Sync now exposes JSON outcomes
  and a comparison-only `--check`, accounts for event rejections and missing downloads,
  matches upload ACKs by ID, and exits nonzero on incomplete transfers. The default
  protocol-progress timeout is 60 seconds. CLI tracing goes to stderr so it cannot
  corrupt JSON summaries or exported event streams.

### Removed

- Removed the deprecated `wok stream` command. Use `wok router` for persistent
  streaming and periodic `wok sync` for reconciliation.

## [0.6.0] - 2026-09-07

### Changed

- Wok runtime databases advance from v4 to v5 with a durable local event
  sequence and transactional author counters. Stop older writers and keep a
  backup before the first writable open; older releases cannot reopen the
  upgraded database. Primary events and payloads are preserved. See
  [upgrade and rollback guidance](https://github.com/erskingardner/wok/blob/v0.6.0/docs/lmdb-v3.md#wok-v4-to-v5).
- Author counters initialize only when requested, normally for quota checks,
  and remain current after initialization. Deployments without author quotas
  avoid creating unused counters; existing quota and durability defaults remain
  unchanged.
- Historical queries share visibility checks and bound candidate scanning;
  selective-author planning avoids unnecessary broad-tag scans. Raw payload
  decoding avoids a copy, live monitors limit content parsing to relevant
  subscriptions, and persistent negentropy tree updates batch within the
  writer transaction.
- Maintenance mutations run through the single writer, with publication and
  synchronization responsibilities split into dedicated modules.

### Security

- Negentropy uses direct persistent trees only when the view is provably public;
  temporary views apply the same authorization, moderation, expiration and
  recipient visibility as other reads. Authorization changes invalidate affected
  sessions.
- Sync sessions share configurable memory reservations, defaulting to 256 MiB
  per connection and 1 GiB across workers, with a 60-second idle timeout and no
  fixed lifetime for active synchronization.
- COUNT/HLL and search apply per-event visibility before counting or ranking.
  LMDB cursor and raw-payload borrows remain tied to their owning transaction.

### Fixed

- Batch sorting preserves each publication's receipt and publisher ownership.
- Unix frame decoding survives concurrent outbound traffic, and both transports
  cancel blocked connection I/O while retaining in-flight byte reservations.
- Replacement and deletion quota checks use net storage effects. Event sequence
  values are not reused after deleting the newest record, and expired events
  are excluded from reads before maintenance removes them.
- The locked dependency graph and workspace APIs support the declared Rust 1.85
  minimum version, with CI explicitly selecting that toolchain.
- Lifecycle conformance tests wait for negentropy close processing before
  asserting unrelated replies, avoiding a race with in-flight revocations.
- Benchmark commands return a failing exit status when any trial fails, after
  preserving JSONL results, the summary, and corpus metadata for diagnosis.
- Benchmark fanout subscribers read concurrently with publication, verify payloads
  using shared expectations, and report aggregate trial time consistently.
- Benchmark idle clients answer WebSocket pings throughout connection setup and
  hold periods, avoiding false disconnect failures in long capacity tests.
- SIGTERM now follows the graceful relay shutdown path, including Unix socket
  cleanup. A CLI process test verifies acknowledged data survives shutdown.
- strfry migration creates Wok extension tables in the private staging copy and
  verifies target integrity before promotion; a real C++ import regression checks
  source preservation and exact event identity.
- Integrity checks now validate v5 state encodings, stored author counts against
  primary events, and sequence high-water marks. Reindex accepts rebuildable
  author-count corruption while refusing detected sequence corruption.

### Added

- NIP-42 supports multiple authenticated public keys on one connection, with
  transport-level conformance coverage.
- Portable Docker relay/load lab with local and two-VM SSH campaigns, bounded
  workloads, preserved artifacts, and shutdown/integrity correctness gates.
- Generated WebSocket/Unix lifecycle tests compare history, live events, COUNT,
  and sync with an independent privacy model, including AUTH and revocation.
- CI runs benchmark correctness tests, native behavioral suites on all four
  distribution platforms, mandatory pinned C++ migration tests, broader seeded
  fuzzing, and a repeatable Linux soak with resource and restart checks.
- Process-kill regression coverage for atomic v4-to-v5 upgrades and event,
  counter, and sequence commits, including lazy state initialization.
- MAP_FULL rollback coverage for staged event and counter changes.
- Controlled soak, storage-write and search-layout experiment reports. The
  event-local phrase index prototype remains unmerged and is not in this release.

## [0.5.0] - 2026-09-03

### Changed

- The default normalized event ceiling is now 1 MiB, with 2 MiB WebSocket and
  Unix message ceilings, so bounded extended-length NIP-44 payloads such as
  kind 1059 gift wraps and kind 445 MLS group events can pass through the
  relay. All three settings remain operator-configurable and retain the 16 MiB
  hard ceiling; explicitly configured 64 KiB deployments are unchanged.
- Oversized normalized events are rejected before event-id hashing and Schnorr
  verification, limiting the extra admission cost made reachable by the larger
  transport envelope.

### Fixed

- WebSocket and Unix connections now share explicit transport metadata and a
  cancellation-safe lifecycle guard, so an abandoned connection task cannot
  leave behind a stale relay registration or inflated active-connection gauge.
- Filesystem capacity checks now convert `statvfs` fields without assuming
  platform-specific integer types.

## [0.4.0] - 2026-08-18

### Added

- Draft NIP-91 `&` tag filters now require every listed tag value for
  historical queries, live subscriptions, COUNT, search, router post-filtering,
  and negentropy. NIP-11 advertises NIP-91 plus the distinct-tag and aggregate
  AND-entry limits. Outbound router `REQ`s and `wok sync` `NEG-OPEN`s keep `&`
  clauses only for upstreams whose NIP-11 document advertises NIP-91, and
  otherwise fold each `&x` value set into the `#x` compatibility clause and
  apply the exact AND semantics locally.
- The pinned NIP-86 relay management API is available over authenticated HTTP
  POST when the operator surface is enabled. It supports persistent pubkey and
  event bans, IP blocks, write allowlists, kind policy, report queues, and
  admin/moderator/custom roles. Bans suppress stored events from writes,
  historical queries, COUNT, and live delivery without deleting them, so
  unbanning restores the original records.

### Changed

- Outbound WebSocket clients use Rustls instead of the platform-native TLS
  backend, removing their OpenSSL dependency while retaining native root
  certificate validation.

### Fixed

- WebSocket connections now bound pre-upgrade HTTP header reads and idle gaps
  while partial frames or fragmented messages are buffered, and close when an
  automatic ping remains unanswered for a full ping interval. Both new read
  deadlines are configurable and can be disabled explicitly.
- Live config reload warnings now cover NIP-42 read restrictions, NIP-62, and
  negentropy scope changes, including the exact restricted kinds dropped by a
  fail-open rewrite.

## [0.3.1] - 2026-08-15

### Fixed

- The landing page footer no longer renders `Wok <version> (unknown)` on
  builds without an embedded commit hash (for example release archives built
  from a tarball); the revision parenthetical is shown only when a real hash
  is available.
- Write-policy plugins that print non-JSON lines to stdout (startup banners,
  debug output) no longer wedge every publication until the round-trip
  deadline and kill the plugin: like C++ `PluginEventSifter`, unparseable
  response lines are logged and skipped while waiting for the response that
  echoes the request's event id. Previously such a plugin made every EVENT
  fail with `error: internal error`.

## [0.3.0] - 2026-08-14

### Added

- The scheduled fuzz campaign now also covers btree node decoding, the
  flatbuffers decoders, and non-empty vector handling.

### Changed

- WebSocket frame handling, the event write pipeline, and event protocol
  parsing were streamlined to reduce per-frame and per-event allocations.
- README benchmark results now reflect the complete post-hardening two-host and
  same-host campaign at `fa9b061`.
- Size-class configuration settings are clamped to a 16 MiB ceiling, abuse
  budgets and guards now surface "0 = unlimited" instead of failing closed,
  configuring `real_ip_header` warns loudly, and security-scope changes are
  warn-logged on hot reload.
- Security documentation now records that the mesh CLI dials arbitrary URLs by
  design, that precomputed negentropy trees interact with restricted kinds,
  the semantics of `restrict_read_to_involved_pubkey = false`, the
  CRIME/BREACH caveat on `compression_sliding_window`, and that `/metrics` is
  public and cross-origin readable.

### Fixed

- Negentropy reconciliation bounds its work and propagates storage errors,
  rejects zero-item nodes, validates node structure on migration, and no
  longer underflows on zero-item btree nodes.
- The Unix transport closes its socket-path race windows and, on orderly
  shutdown, removes its own socket pathname by tracking the pathname's
  filesystem identity across the atomic bind rename, while preserving a
  socket that replaced it.
- The CLI resolves `lsof` at absolute paths during migration, exits quietly on
  EPIPE instead of panicking, validates router `connectionTimeout` against a
  ceiling, splits `parse_mesh_time` on char boundaries, bounds stdin line
  buffering in import/upload/monitor, bounds stream/router buffering of
  unverified mesh events, and bounds `wok sync` memory growth from malicious
  peers.
- Search scans short-circuit when the limit is 0, COUNT dedup-set growth is
  bounded by a total budget, and the query scheduler recycles its slot on scan
  error.
- LMDB index values are length-checked before u64 conversion, and the fbs
  decoder rejects negative vtable offsets.
- `unix.mode` is masked to permission bits, per-pubkey quota memos survive
  across writer batches, and plugin roundtrips get one overall deadline.

### Security

- The landing page escapes `GIT_HASH` in its template, the admin dashboard
  pins its inline script by CSP hash and burns replay-cache IDs only after a
  2xx response, and plain HTTP endpoints are rate-limited through the
  connection budget.

## [0.2.0] - 2026-08-14

### Added

- A Wok logo used consistently by the repository README, public relay landing
  page, and signed-out and authenticated operator dashboard.
- Comprehensive configuration and Prometheus metric references, including a
  complete commented `wok.toml` and documented dashboard edit boundaries.
- A guarded two-host Wok/strfry campaign runner with deterministic reusable
  signed corpora, realistic actor relationships, historical remote queries,
  lifecycle publication workloads, alternating relay order, and captured
  provenance and resource evidence.
- A same-host, order-rotated transport campaign comparing Wok's production
  length-prefixed Unix interface with Wok and strfry WebSockets under identical
  correctness-gated publish, query, fanout, and connection workloads, plus a
  reproducible report of the first 100,000-event, three-repetition campaign.
- Property tests and a scheduled sanitizer-backed libFuzzer campaign covering
  strict JSON and event validation, protocol envelopes, WebSocket framing and
  decompression, Negentropy frames, and LMDB transaction sequences.
- Storage recovery fixtures that exhaust the LMDB map and terminate a writer
  process before commit, then reopen the database and verify atomicity and
  complete index integrity.
- A least-privilege systemd unit and production deployment guide covering
  filesystem permissions, reverse proxies, plugins, logging, and database
  operations.
- Scheduled locked-dependency advisory, source, and license policy checks.

### Changed

- Event validation no longer clones the complete parsed JSON value after
  producing the packed event and normalized persistence JSON.
- The relay writer skips reparsing normalized event JSON when no write-policy
  plugin is configured.
- NIP-50 search progress bookkeeping is written once per committed event batch
  instead of deleting and reinserting its metadata record for every event.
- Batched database writes borrow packed events and normalized JSON in place,
  avoiding two complete event copies per accepted publication.
- Historical query results now flow directly from the scheduler callback,
  without cloning subscriptions or copying LMDB payloads into an intermediate
  per-timeslice buffer.
- The relay landing page now presents banner/icon media, operator and relay
  npubs, contact and policy links, linked and described supported NIPs, and the
  version with its source revision.
- The operator dashboard now opens on an explicit signed-out screen and
  exposes the broad safe set of live-reloadable identity, event, protocol,
  abuse, filter, NIP-62, and history settings with inline explanations.
- Dashboard charts now include a labeled, automatically scaled value axis.
- Release archives now retain the complete documentation tree, including the
  logo referenced by the packaged README, while keeping `wok.toml` at the
  archive root for convenience.
- NIP-50 indexing bounds unique normalized terms and generated bigrams per
  event, with a schema rebuild for deterministic bounded postings.
- REQ and COUNT admission now enforce both a combined compact-JSON byte budget
  and an unconditional filter-count ceiling.
- New databases default to a 64 GiB LMDB map, a 1 GiB free-disk reserve, and
  finite global and per-pubkey durable event ceilings.

### Fixed

- Dashboard NIP-98 requests now include a cryptographically random nonce, so
  repeated or save-then-refresh actions signed in the same second cannot
  collide with replay protection.
- Untrusted relay notices and plugin diagnostics are emitted as escaped
  structured fields instead of raw terminal text.

### Security

- Safe crates forbid unsafe Rust. LMDB and operating-system FFI are confined
  to explicit audited modules, transaction and cursor wrappers cannot cross
  threads, and Negentropy nodes use validated field encoding instead of raw
  Rust-struct memory copies.
- Durable writes fail atomically at the configured disk, LMDB map, global
  event, or per-author event ceiling, preventing unbounded storage growth.
- CI continuously checks adversarial parser behavior with an
  AddressSanitizer-backed libFuzzer smoke campaign and rejects vulnerable,
  yanked, unapproved, or unknown dependency sources.

## [0.1.0] - 2026-08-13

### Added

- NIP-50 content search with transactional Unicode-normalized term and phrase
  indexing, relevance ordering before limits, structured-filter intersection,
  live subscription matching, automatic migration backfill, integrity/reindex
  coverage, and correctness-checked scale benchmarks.
- A reloadable, request-wide EVENT result ceiling across multi-filter REQs,
  independent of COUNT and negentropy limits.
- NIP-62 Request to Vanish with strict relay targeting, persistent
  maximum-timestamp markers, immediate query and rebroadcast suppression,
  recipient gift-wrap cleanup, undeletable request records, and bounded
  restart-safe physical deletion.
- Mergeable NIP-45 HyperLogLog sketches for canonical single-target COUNT
  filters, including hex, address, and arbitrary-string offset derivation.
- Configurable structured JSON tracing for log collectors, richer correlation
  fields, and hard-bounded in-memory operational metric history for the admin
  UI, alongside the existing Prometheus exporter.
- An optional operator dashboard with NIP-98/NIP-07 authentication, bounded
  replay protection, operational charts, and atomic writes for a deliberately
  small, validated subset of live-reloadable TOML settings.
- Bounded, idempotent negentropy tree builds with configurable scan batches,
  short write transactions, and progress checkpoints.
- Initial Wok release: a Rust Nostr relay with WebSocket and optional
  length-prefixed Unix-socket transports.
- Verified, one-way migration from strfry LMDB v3 into a Wok-owned v4
  database, including a no-write preflight, complete config translation audit,
  event fingerprint verification, and a migration manifest.
- Native TOML configuration with strict unknown-key rejection and safe live
  reload of runtime settings.
- Relay support for NIP-01, NIP-09, NIP-11, NIP-40, NIP-42, NIP-45, NIP-59,
  NIP-70, and NIP-77 behavior, with conditional capability advertisement.
- Optional NIP-13 proof-of-work enforcement advertised through NIP-11.
- `doctor` diagnostics and staged, verified `reindex` recovery with retained
  backups.
- Import, export, scan, event, delete, compaction, dictionary, monitoring,
  router, stream, sync, upload, download, and negentropy tooling.
- Native abuse controls covering connection, EVENT, REQ, and COUNT budgets;
  IP and pubkey token buckets; query-cost and historical-query concurrency
  limits; optional author storage quotas; and labeled rejection metrics.
- Differential strfry compatibility tests, independent NIP conformance tests,
  cross-transport end-to-end tests, property tests, and comparative benchmarks.

### Changed

- The comparative benchmark now emits replayable signed corpora and SHA-256
  manifests, supports repeated order-balanced trials, and includes a remote
  load profile for scaled publication, fanout, and idle connections.
- Wok treats strfry compatibility as a verified migration boundary rather than
  an ongoing promise to preserve strfry implementation bugs.
- Ephemeral event kinds are live-only by default, with an explicit persisted
  TTL compatibility mode for migrations that need strfry behavior.
- NIP-11 capabilities are derived from implemented and enabled relay behavior;
  operators cannot supply an arbitrary advertised NIP list.

### Fixed

- Accepted WebSocket connections now enable `TCP_NODELAY`, preventing Linux
  delayed ACKs from adding roughly 40 ms between small EVENT and EOSE frames.
- Historical result bursts no longer hit an undocumented 256-message queue
  and disconnect healthy clients before the configured pending-byte budget;
  deep author pagination and mixed read/write workloads now guard this path.
- Private kinds 4 and 1059 now fail closed by default, broad COUNT requests
  cannot leak restricted-event populations, and NIP-59 is advertised only
  when AUTH, recipient filtering, gift-wrap deletion, and live-only kind 21059
  behavior are all usable.
- `wok stream` now reconnects after connection failures and remote closes with
  non-blocking capped exponential backoff, while retrying the first local event
  whose WebSocket send did not complete.
- Hardened malformed LMDB comparator handling and semantic verification of
  every derived event index.
- Corrected subscription installation ordering so immediate live events cannot
  race ahead of EOSE.
- Corrected strict NIP-01 filter grammar, event validation, AUTH propagation,
  negentropy session lifecycle, error routing, slow-client handling, database
  watching, and write-policy timeout behavior found during differential review.

### Security

- Bounded JSON nesting, frame/message sizes, outbound queues, plugin execution,
  query work, publication rates, and optional per-author storage.
- Protected-event publishing and restricted reads require the appropriate
  authenticated author or recipient relationship.

[Unreleased]: https://github.com/erskingardner/wok/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/erskingardner/wok/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/erskingardner/wok/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/erskingardner/wok/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/erskingardner/wok/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/erskingardner/wok/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/erskingardner/wok/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/erskingardner/wok/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/erskingardner/wok/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/erskingardner/wok/releases/tag/v0.1.0
