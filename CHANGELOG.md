# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Update zstd to 0.14.3 (zstd-safe 8.2.0, zstd-sys 2.1.2) for
  RUSTSEC-2026-0391, -0398, -0403 and -0410 (stream state reused after an
  abandoned stream, `Seekable::decompress`, legacy-frame streaming
  decompression, and the WebAssembly allocator shim). Wok uses only zstd's
  bulk compressor, decompressor and dictionary training, none of which the
  advisories affect, and the bundled libzstd stays at 1.5.7, so stored
  payloads compress and decompress as before.
- NIP-42 AUTH compares the scheme and path of its `relay` tag with those of
  `relay.auth.service_url` (#167). Only the host and port were compared, as
  in strfry, so where one host serves several relays by path, a relay at
  `wss://host/a` accepted an AUTH signed for `wss://host/b`: a co-tenant
  relay could pass its own challenge to a user and sign in as them here.
  The path is compared as written, case included, and `ws` differs from
  `wss`; the host's case, a query, trailing slashes and the port the scheme
  implies are ignored, and `https` and `http` count as `wss` and `ws`.
  **Set `service_url` to the URL clients connect to, scheme and path
  included**: a relay served at `wss://host/relay` whose `service_url` is
  `wss://host`, or `ws://host/relay`, now refuses its clients' AUTH with
  `incorrect or missing relay tag`. NIP-62 vanish requests' `relay` tags
  are compared the same way: a default port or query no longer stops one
  from matching, and the path's case and the scheme now do.
- The relay warns at startup, and `wok doctor` in a new `unix-access` check,
  when the Unix socket's mode lets every local user connect, as `0o666` does,
  and `relay.unix.auth_uids` and `auth_gids` are both empty (#167). Unix
  connections skip the connection, per-address and per-connection budgets,
  so such a socket gives each local user a channel that only proof of work,
  the storage quotas and the per-author EVENT budget limit, and an
  unauthenticated connection starts that budget afresh with each new key.
  NIP-62 vanish requests skip proof of work and the quotas (#248), so the
  disk reserve is what bounds a peer that signs one with each new key.
  docs/production-deployment.md now says what a write-policy plugin's
  request carries: `authed` is present only for NIP-70 protected events and
  owner-only kinds, so a plugin cannot use it to tell who is logged in, and
  `sourceType: "unix"` names the transport, not a trusted caller.
- `wok migrate strfry` verifies every event against its stored payload
  before it migrates the database (#55). The payload must name the packed
  record's id, pubkey, kind and created_at, hash to that id, and carry a
  valid signature by that pubkey. The packed record, which every index,
  recipient-only read, replacement, deletion and expiry uses, must index
  nothing the payload does not carry: each packed tag is one of the
  payload's (or the empty `d` strfry adds), a replaceable or addressable
  event keeps the payload's address, the first recipient is the payload's,
  and the expiration is the one strfry writes. Integrity checked only that
  the indexes match the packed records, so a strfry database written by
  `strfry import --no-verify` or `--fried`, or edited by hand, could migrate
  an event the relay then served for queries it does not match, filed under
  a recipient, address, deletion target or expiry its author did not sign,
  or not signed at all. A source holding such an event is refused, and up to
  100 of them are named by local ID, id and reason; `--check` reports the
  same. Verification spreads over every core, or half of them for `--check`,
  which may run beside strfry: a million events took about 4 s on a 14-core
  Apple M4 Max.
- A file that gives a kind more readers than its preset does is warned about
  when the relay starts, and by `wok doctor` in a new `read-classes` check
  (#163). `relay.auth.recipient_only_kinds = []`, `owner_only_kinds = []` or
  a gift-wrap kind moved to `authenticated_kinds` were named only by a
  reload's "read access WIDENED", so a relay started with such a file served
  those kinds more widely without a word. The warning names each kind with
  its class in the preset and in the file.
  - **`preset = "marmot"`** refuses to start or reload unless kinds 1059 and
    21059 are recipient-only (or owner-only), as it refuses without usable
    AUTH. Before, `recipient_only_kinds = []` served Welcome gift wraps, `p`
    tags included, to anyone.
  - **Inbox kinds** that are not recipient-only are warned about under
    `write_policy = "members"`, at startup, on the reload that makes one and
    in a new `inbox-kinds` doctor check: outsiders may publish them,
    addressed to a member, for others to read. docs/config.md now says that
    an inbox event's `OK true` tells an outsider that its `p` key is a
    member.
  - **Events nobody could read** are refused while AUTH is unusable, as
    owner-only kinds already were: an event of a recipient-only or
    authenticated kind, such as a gift wrap on the `default` profile, gets
    `restricted: kind 1059 is read only after AUTH, which this relay does not
    offer`, by its kind before its signature is verified, and again by the
    writer, so one queued before a reload made AUTH unusable is refused too.
    Before, it was stored and every read of it refused. NIP-62 vanish
    requests are still accepted whatever their class.
- A reload that tightens `relay.filter_validation` closes the REQ
  subscriptions, COUNTs and NEG sessions whose filters it now refuses (#164).
  The rules were checked only when a REQ, COUNT or NEG-OPEN arrived, so
  turning on `require_scoped_filters` to stop `{"kinds":[445]}` enumeration
  left those subscriptions sending the rest of their history and then every
  new event. Each is closed with the `CLOSED` or `NEG-ERR` it would get if
  sent now, and counted once in `wok_refusals_total` under the rule that
  refused it; one still sending history stops at its next time slice.
- NIP-86 `blockip` closes the WebSocket connections already open from the
  address (#164). The block was checked only when a connection opened, so
  the client it was meant to stop kept reading and publishing on the
  connection it had until that closed.
- A guard the file sets to zero, turning it off where its preset keeps it,
  is warned about when the relay starts and by `wok doctor` in a new
  `zero-guards` check, not only on reload and on the dashboard (#164). A
  relay started with `relay.abuse.max_query_work = 0` or
  `relay.handshake_timeout_secs = 0` logged nothing.
  `relay.max_live_buffer_bytes` and `database.min_free_disk_bytes` are now
  guarded too; the second, a restart setting, is warned about once it
  applies. A
  `relay.abuse.min_pow_difficulty` above 0 under `relay.abuse.enabled =
  false`, which ignores it, is warned about at startup, on the reload that
  causes it, and in the `abuse-limits` doctor check.
- A reload that makes AUTH unusable ends every login (#164). Each thread
  serving a connection kept the keys it had authenticated as, so after a
  reload turned `relay.auth.enabled` off or emptied `service_url`, a
  logged-in connection still read its gift wraps and DMs, which nobody is
  meant to while AUTH is off, and went on reading them once a reload made
  AUTH usable again. The connection is now anonymous from that reload on:
  the NEG sessions it opened while logged in are closed with `closed:
  authentication changed; reopen synchronization`, its live subscriptions
  deliver nothing only its keys may read, and once AUTH is back it
  authenticates again with the challenge it holds.
- The writer checks NIP-70 protected events and `relay.auth.owner_only_kinds`
  again under its own configuration before it stores or broadcasts them, as
  it does `accepted_kinds` and the write policy. An event queued before a
  reload made AUTH unusable, or moved its kind into `owner_only_kinds`, was
  stored and answered `OK true`; it now gets the refusal the ingester would
  give, counted under `owner_only_kinds` unless the event is protected, but
  `restricted:` instead of `auth-required:` when the connection holds no
  challenge, which only the ingester can issue. NIP-62 vanish requests are
  still exempt.
- Limits on what an unauthenticated client can make the relay hold or do
  before its budgets apply:
  - **Compressed messages** may inflate to half of
    `relay.max_websocket_payload_size` plus 64 KiB whatever their
    compression, which holds the largest event, and past that to at most 32
    times their compressed size, never past the maximum. A message past its
    limit is refused as too large.
  - **Each connection's queued messages** are bounded: a connection may have
    at most the largest message a transport accepts, in bytes, and at most 64
    messages, waiting for the ingester. Its next message is held until there
    is room, and the transport stops reading once its hold is full, while it
    keeps writing to the client. A WebSocket read is decoded about a maximum
    message at a time. Before, one connection could fill the shared ingest
    queue.
  - **NEG-CLOSE** is handled by the negentropy worker as one removal each, in
    a run, instead of a configuration copy, read transaction and pass over
    every session per message.
  - **NEG-OPEN** meets `relay.max_req_filter_size`, and a connection's
    sessions share `relay.max_filter_bytes_per_connection`, as REQs and
    COUNTs each do. Its payload is decoded after its filter is checked.
  - **A partial WebSocket message** must arrive whole within
    `relay.message_read_timeout_secs` (new, 120 seconds) of its first byte.
    `relay.frame_read_timeout_secs` bounds only the gap between reads, so a
    client sending a little at a time could keep a message of up to
    `relay.max_websocket_payload_size` buffered indefinitely. A pause while
    the relay does not read, because the connection's hold is full, does not
    count.
  - **Connections per address**: an address may hold at most
    `relay.abuse.max_connections_per_address` (new, 256) WebSocket
    connections open at once, keyed like the other per-address budgets (its
    IPv6 /64, the `real_ip_header` address). Every per-connection limit,
    such as the inbound share and the outbound queue, otherwise multiplied
    by however many connections one host kept open; the connection budget
    limited only how fast it opened them. An upgrade past the cap gets 429
    and is counted in `wok_refusals_total`.

- Requests are refused by the cheapest check that can refuse them, before
  their filters are parsed or their signature is verified, where that
  reveals nothing:
  - **AUTH** checks its kind, the connection's challenge and the relay tag
    before verifying the signature (#148).
  - **REQ, COUNT and NEG-OPEN** meet `relay.auth.read_policy` before their
    filters are sized, parsed or priced and, for NEG-OPEN, before the payload
    is decoded (#149).
  - **COUNT** is refused while disabled before it spends the COUNT budgets,
    and a REQ over the connection's subscriptions, or a REQ or COUNT over its
    filter bytes, before its filters are parsed, validated and priced (#165).
  - **EVENT** is refused for its kind, by `relay.auth.accepted_kinds`, the
    NIP-86 kind policy or as an AUTH event, before it is verified (#150). The
    author ban and `write_policy` still wait for the signature, so an
    unsigned event cannot ask whether a key is a member or banned.
  - **EVENT** short of `relay.abuse.min_pow_difficulty`, counted from the id
    it states, and a vanish request while NIP-62 is off or whose `relay` tags
    do not name this relay, are refused before it is verified too (#165).
  - **The dashboard API and NIP-86** check a request's `Nostr`
    authorization before reading its body: the event's kind, content, time
    window and tags, then whether its signer may use the endpoint, and only
    then the signature (#147). Only the `payload` hash and the replay check
    wait for the body, so a request that could never be authorized is
    refused without waiting for one; the time window is checked again once
    the body has arrived. A signer that may not and a bad
    signature get the same 401, "NIP-98 authorization is not from a key
    allowed here, or its signature is invalid", so a forged event cannot ask
    which keys are admins or managers; the debug log records which. The
    authorization event is parsed by Wok's strict JSON parser.

  Some refused requests therefore get a different reason than before, such
  as `challenge string mismatch` instead of `invalid: bad signature` for an
  AUTH that is wrong both ways.
- Prometheus metrics are off by default (#151). `/metrics` was served on the
  relay listener in every configuration, with `Access-Control-Allow-Origin: *`,
  so anyone who could reach the relay, and any web page, could read its
  connection, AUTH, abuse and refusal counters. `observability.metrics_enabled`
  turns them on, and reloads live. `observability.metrics_listen` (restart)
  serves them on a listener of their own, which answers only `GET /metrics`,
  without CORS headers, while the relay listener answers `/metrics` with 404.
  That listener applies NIP-86 IP blocks and the per-address connection
  budget like the relay listener. The relay warns, at startup and on a reload
  that causes it, when metrics are served on a relay listener or a
  `metrics_listen` address reachable beyond loopback and private addresses,
  and turning them on or off is logged as a security-scope change. A reload
  that changes `metrics_listen` is logged and applies at restart; a relay
  started without one keeps metrics off until then. **Upgrading:** a relay scraped at `/metrics`
  must set `metrics_enabled = true`, preferably with `metrics_listen` on a
  private address, and point Prometheus there.
- NodeInfo is off by default (#166). `/.well-known/nodeinfo` and
  `/nodeinfo/2.1` were served in every configuration, though no Nostr client
  or Marmot client uses them and NIP-11 already gives the software and its
  version, and the discovery link repeated the request's `Host` header, which
  a cache in front of the relay could hand to other clients (#152).
  `relay.nodeinfo_enabled` turns them on, and reloads live; while it is off
  both paths answer 404, and turning it on or off is logged as a
  security-scope change. Discovery now links to `/nodeinfo/2.1` on the origin
  of `relay.auth.service_url`, or else `admin.public_url`; with neither set it
  answers 404, and the relay and `wok doctor` warn. **Upgrading:** a relay
  that should stay listed by NodeInfo crawlers must set
  `relay.nodeinfo_enabled = true`, and `relay.auth.service_url` or
  `admin.public_url`.
- With `relay.real_ip_header` set, a client could escape a NIP-86 `blockip`
  by sending its own X-Forwarded-For. A proxy that appends the client's
  address to that header (nginx's `$proxy_add_x_forwarded_for`) passed Wok a
  list, which it could not parse, so the client got the proxy's address. One
  that adds its own line after the client's (HAProxy's `option forwardfor`)
  left the client's line first, which Wok read, so the client chose its
  address and could spend another address's budgets. Wok now reads the
  header's last entry, the address the proxy wrote, and accepts a port. A
  last entry that is not an address still falls back to the connecting
  address, but is counted by `wok_real_ip_header_unparsed_total` and warned
  about at most once a minute. Relays without `real_ip_header`, the default,
  and proxies that replace the header are unaffected.
- Reloads that move a trust boundary say so (#164). A reload that sets or
  changes `relay.real_ip_header` or `relay.trusted_proxies`, which apply to
  the next connection and request, logs the warning the relay gives at
  startup, which now names NIP-86 IP blocks and the write-policy plugin's
  `sourceInfo` beside the per-address budgets. Changes to `admin.enabled`,
  `public_url`, `pubkeys`, `allow_config_writes` and `auth_window_secs` are
  logged as security-scope changes, naming each key added and removed, and
  a key removed from `admin.pubkeys` that still holds the NIP-86 `admin` or
  `moderator` role, which it keeps, is warned about. Each authorized NIP-86
  request is logged with its method.
- A members-only relay accepts its members' events from throwaway keys.
  `relay.auth.restrict_writes` checked only the event's author, so an
  allowlisted relay refused every Marmot group message (445) and gift wrap
  (1059), which are signed by fresh or random keys (#97 C7). Its replacement,
  `write_policy = "members"`, also admits an event sent on a connection
  authenticated as a member, and, for `relay.auth.inbox_kinds` (default
  `[1059, 21059]`), one whose first `p` tag is a member. The writer checks
  that member again against committed moderation state.
- NIP-78 app data (kinds 78 and 30078) is private to its author, as NIP-78
  recommends. It is served only to a connection authenticated as the author
  and accepted only from one: an EVENT without AUTH is refused with
  `auth-required:` and a challenge, and one sent on a connection
  authenticated as another key with `restricted:`. Before, anyone could read
  or publish it (#97 B13). NIP-78 is now advertised while AUTH is usable.
- Events from throwaway keys are charged to the AUTHed identity that sent
  them. On a connection that has authenticated, an event whose author is not
  one of its identities, such as a Marmot 445 signed by a fresh key or a
  1059 gift wrap, now draws on the per-author EVENT budget
  (`relay.abuse.pubkey_event_*`) of the connection's first identity. Before,
  each event was charged to its own new author, so the budget never applied
  to them. The refusal is `rate-limited: EVENT budget exhausted for the
  authenticated pubkey`. Unauthenticated connections and the per-author
  storage quota still key on the author (#97 F11).
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
- NIP-62 vanish requests (kind 62) now pay the per-author EVENT budget like
  any other event. Before, a validly signed vanish request skipped it and only
  the per-address budget limited them. They still bypass the write-policy
  plugin and NIP-13 proof of work, now documented: NIP-62 requires relays that
  restrict who can post to honor vanish regardless of the user's status
  (#48, #248).
- A NIP-62 vanish request that targets the relay is now stored when the
  relay is at its global storage quota (`relay.abuse.max_stored_events`), and
  its author's events are then deleted (#248). Before, the request was
  refused with the rest of its writer batch, so nobody could vanish from a
  full relay, though NIP-62 says a relay MUST honor the request. The quota no
  longer counts a batch's vanish requests: when the rest of the batch is over
  it, they are written on their own and everything else is refused as
  before. On a full relay, or one that requires proof of work, anyone can
  therefore store a vanish request with each fresh key. The per-address
  EVENT budget (which a Unix connection skips), the per-author EVENT budget
  and the disk reserve (`database.min_free_disk_bytes`) bound them, and the
  NIP-86 kind policy,
  event-id bans, blocked addresses and `relay.nip62.enabled` still refuse
  them (see docs/attack-surface.md).
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
- A used NIP-98 authorization could be replayed after two reloads of
  `admin.auth_window_secs` (#164). The replay cache was pruned by the current
  window, so with a window of 300 an event used 30 seconds ago was dropped
  by any request after a reload to 5, and accepted again, body and all,
  after a reload back to 300. The cache now keeps each ID for 300 seconds,
  the longest window the setting allows, whatever the current window, and
  holds up to 20,480 IDs instead of 4,096, so a manager can make as many
  requests a minute as before.
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
- `wok download` verifies each event's id and signature before printing it,
  as `wok import`, `wok sync` and `wok router` already did (#154). Before, it
  printed whatever the relay sent, so used on its own rather than piped into
  `wok import` it passed a malicious relay's forged events through. An event
  that fails, or a message that is not JSON, is skipped and logged on stderr
  with the reason, and the command exits nonzero with the number skipped.
  It also exits nonzero when the connection closes before EOSE; before, a
  dump cut short exited 0, and a ping or close frame ended it with a JSON
  error. Events print in the normalized form `wok export` writes.
  `--no-verify` skips the id and signature checks, like `wok import
  --no-verify`.
- New database files are created with mode `0640`, less the umask, instead
  of `0664` (#56): `data.mdb` and `lock.mdb`, `wok compact` output and the
  copy `wok migrate strfry` takes. Stored events include gift wraps and
  other recipient-only kinds, which any local user who could reach the
  database directory could read unless the umask removed other users'
  access. Existing files keep their mode: `chmod g-w,o= data.mdb lock.mdb`
  in the database directory narrows them. The example systemd unit's
  `UMask=0077` and `0700` state directory already kept other users out.
- Any key could stop expiry and NIP-62 deletion for the whole relay (#240).
  The count of a key's events that `relay.abuse.max_stored_events_per_pubkey`
  checks against, built from the author index the first time it is needed,
  skipped the key's events at `created_at` 0. A kind 62, which the quota
  does not check, could be stored at 0 before the count was built. Once the
  key's counted events were deleted, the next deletion found the count at
  zero and aborted its transaction: maintenance retried the same expired
  events every 2 seconds and failed each time, and a deletion request
  aborted the writer batch it was in, other clients' events included, with
  `error: author count overflow or drift`. The count now includes those
  events. A count that a deletion still finds at zero, as an earlier release
  may have stored, is dropped with a warning and counted again from the
  author index when next needed; `wok_author_count_drift_total` counts them,
  and `wok reindex --confirm-relay-stopped` drops every stored count. The
  same scan let a NEG-OPEN be answered from the persistent negentropy tree
  while it held an event of a restricted kind at `created_at` 0, and made
  the NIP-62 backfill miss requests at 0. A request at `created_at` 0 now
  leaves a marker like any other, so the key's events at 0 and the gift
  wraps that p-tag it are deleted; before, it was stored and did nothing.
- `wok reindex` keeps the NIP-86 moderation records (#241). It copied the
  other tables that events don't derive but not `wok_Moderation`, so the
  database it promoted had no bans, allowlist entries, roles, kind policy,
  IP blocks or reports: banned pubkeys and events were served again, every
  kind was accepted, pubkeys given the `admin` or `moderator` role lost
  management access, and under the `members` policies only `admin.pubkeys`
  were still members. **A database reindexed by an earlier release has lost
  these records**, but the backup reindex kept
  (`<database>.pre-reindex-<timestamp>`, or the `--backup` path) still holds
  them. With the relay stopped, `mdb_dump -s wok_Moderation <backup> |
  mdb_load -s wok_Moderation <database>` copies them back. Each replaces
  the record with the same key, and records under other keys stay. That also
  undoes what changed since the reindex, such as a lifted ban, a revoked
  role or a new kind map, so then repeat, in order, every NIP-86
  management call made since, before letting clients back in. After more
  than one such reindex, restore from the backup the first one kept and
  repeat every call made since then.
- A NIP-77 message to a session served from a negentropy tree costs a
  tenth of the worker time it did, and sessions take turns with their
  client (#254). To read the item count of each node it passed, a lookup in
  the tree decoded all 3,952 bytes of it, again for every lookup, so one
  crafted 82 KB NEG-MSG cost about 2.7 s of CPU on a tree of 2 million
  events. A connection could send `relay.abuse.per_connection.neg_msg_burst`
  (200) of them at once and queue minutes of work on one of the two
  negentropy workers, ahead of every other sync it serves. Lookups now read
  only a passed node's count and accumulator, in place, as strfry does, and
  keep them for the rest of the message, so that message costs about
  0.2 s. A NEG-MSG sent before the relay's reply to its session's NEG-OPEN
  or previous NEG-MSG now closes the session with `invalid: NEG-MSG sent
  before the reply to NEG-OPEN` or `invalid: NEG-MSG sent before the reply
  to the previous NEG-MSG`, whether a tree or a view built in memory serves
  it; before, only one sent while a view in memory was still being scanned
  did. **A client that sends a NEG-MSG before reading the reply to its last
  one now gets NEG-ERR**: NIP-77 has the two sides take turns, and `wok
  sync` waits for each reply.

### Added

- `wok-bench --scenario db_write` times storing events without a relay or
  the network (#257). It loads a corpus into a fresh database, then writes
  the corpus's last events through the relay writer's storage calls in
  durable transactions of each `--db-batches` size (1, 8, 64 and 512 by
  default). Per batch size it reports stored events per second, transaction
  and commit percentiles, and on Linux the bytes written per stored event
  and pages per commit; duplicates and superseded or deleted events are
  counted apart. The database lives under `--dataset-dir`, so a tmpfs `/tmp`
  does not hide the disk.
- `wok-bench --scenario codec_cpu` measures the CPU each message costs on
  the publish and delivery paths (#257), in process on one thread: the
  client's EVENT message parsed as the relay parses it, the event packed,
  its id hashed and its signature verified, and WebSocket frames decoded
  and encoded with and without permessage-deflate. Every result is checked,
  and the summary gives the publications per second one core can take
  through the inbound steps.
- Writer metrics (#257): histograms of how many messages were queued when
  the writer started a batch, how many events each commit holds, and how
  long the batch's checks, writes, commit and replies took
  (`wok_writer_*`), plus the bytes its transactions sent to storage on
  Linux. Publishing is bound by the single writer, so these show where an
  event's EVENT→OK time goes and what each event costs to write.
- `wok-bench`'s `live_fanout` keeps up to `--fanout-window` publications
  unacknowledged (256 by default; `FANOUT_WINDOW` in the campaign scripts)
  instead of waiting for each OK before the next (#257). It measured publish
  round trips rather than delivery: 128 subscribers took 64,000 events in
  4.2 s on Wok master, about one event per 8 ms OK. `--fanout-window 1`
  keeps the old behavior, so earlier results are comparable only with it.
- `scripts/benchmark-campaign.sh` records what each phase made the relay
  write (#257): the relay host's helper marks the relay process's storage
  I/O before and after every phase, and each phase's results get a
  `relay-io.json` with the bytes read and written, and for a fixed-rate step
  the bytes written per newly stored event. It works for any relay, strfry
  included.

- `scripts/benchmark-campaign.sh` compares any number of relay targets
  (#226), each described by a file on the relay host, instead of one Wok and
  one strfry. Each relay runs as a transient systemd unit, which
  `RELAY_CPUS` pins and `RELAY_MEMORY` caps, page cache included, and the
  helper fails the run when a requested limit is not in effect. Every start
  drops the page cache, and `CACHE=warm` reads the database in first. Imports
  are kept as snapshots and restored on later repetitions, and `LOAD_CPUS`
  pins the load generator, so it can run beside the relay over loopback. The
  relay and load hosts are required settings: the scripts no longer default
  to the old benchmark hosts' addresses.
- `wok-bench --event-mix social --generate-corpus-only` writes a public
  social relay's history at the scale of a large benchmark database: 100,000
  authors with Zipf activity over two years, a reaction-, note- and
  list-heavy kind mix, and real event sizes, such as follow lists of up to
  2,000 follows and Marmot Welcomes (#226). Profiles and lists are replaced
  and deletion requests delete, and the manifest gives the number of events a
  relay keeps, which strfry 1.1.3 and Wok match on import.
- `wok-bench` reads a social corpus (#226): `ws_query_latency`,
  `deep_history_pagination` and `mixed_read_write` take `--event-mix
  social`, and expect what a relay keeps of the corpus after replacements
  and deletions, which strfry 1.1.3, Wok 0.7.0 and Wok master all match.
  `ws_query_latency` then sends #226's archive reads: id lookups, profiles
  and feeds of 500 followed authors, `#p` notifications and followers, and
  `#e` threads. Every read scenario now accepts any of a second's events
  where a `limit` cuts through it, since strfry and Wok send a second's
  events in arrival order rather than lowest id first; a social corpus has
  many such seconds. A relay the harness starts is checked by its export
  rather than by import's exit status, and gets the event limits the corpus
  needs. The read scenarios now work out expected replies before timing,
  time each REQ to its EOSE, and leave reply checks out of throughput. The
  harness streams the corpus and keeps about 250 bytes of each event, so a
  50M-event corpus needs about 13 GB rather than 285 GB, and a historical
  REQ may take 120 s rather than 10 s to reach its EOSE.
- `scripts/benchmark-qualify.sh` checks that two benchmark hosts are fit to
  measure on (#226). It records their hardware, and measures sync-write
  latency and random reads on the relay's database filesystem, the network
  between the hosts, and steal time with every CPU busy. It fails when
  either host's average steal is above 1 percent and, given an earlier run,
  when the sync-write p99 has moved by more than 2x.
- `wok-bench --scenario ws_publish_rate` publishes at a fixed rate without
  waiting for replies (#226), so a relay that falls behind builds a backlog
  that its latency shows, instead of slowing the sender. Every event's send
  time and reply go to an outcome log, and `--reconcile` compares the log
  with the relay's export: each event was acknowledged and stored,
  acknowledged but lost, refused (counted by reason), or unanswered and then
  stored or not. A relay the harness starts is reconciled when the run ends,
  and a lost write or a stored refusal fails the trial.
- `wok-bench --scenario clients` drives any relay by `--target-url`, such as
  strfry or a Wok release, not only a Wok the harness starts (#226).
  `--target-max-filter-limit`, `--target-max-events-per-req` and
  `--target-recipient-kinds` give it the remote relay's limits, and
  `--generate-corpus-only --scenario clients` writes the corpus that relay
  must hold. Before the clock starts, the run checks that the relay holds
  both corpora and nothing an earlier run published. With
  `--client-arrival-rate` and `--client-session-secs`, client sessions start
  and end on a fixed schedule. Connections, re-REQs, background publications
  and Marmot bursts count their latency from when they were due; a re-REQ
  due behind an unfinished one waits and keeps its due time. Background
  publishers must hold their rate, counting a publication as sent once it is
  written to the socket, and a reconnecting publisher skips the slots it
  missed instead of sending them in a burst. A session sends nothing new
  after its visit ends. Requests left unanswered, duplicate live deliveries,
  and connections the relay refused, dropped or closed are counted, by
  reason for refusals and closes. Like refusals, they fail the trial only
  with `--expect-no-refusals`. Errors are kept for failures of the load host
  itself. Background publishers now also send
  `X-Forwarded-For`, and `--clients-per-address 0` turns it off for them as
  for clients.
- `scripts/benchmark-campaign.sh` can import the social corpus
  (`CORPUS_MIX=social`) and measure publication capacity (#226). With
  `RATE_STEPS`, each relay publishes at fixed rates that rise step by step
  until one misses its targets: everything sent on time, accepted and
  answered within `RATE_P99_MS`. The last step that met them is recorded as
  the relay's capacity. Once the relay stops, every step's outcome log is
  reconciled with its exported database, and a lost write or a stored
  refusal fails the campaign. The query phases read the social corpus too.
- `wok-bench --scenario nip77_catchup` measures NIP-77 catch-up against a
  relay that holds a corpus (#226): an archive mirror syncing the corpus in
  time windows, or a Marmot app syncing each group's 445 messages at start.
  The client holds all but the newest or a random share of the events, runs
  the NEG-MSG rounds, then fetches what it lacks. It reports rounds, bytes
  each way, time to reconcile and to fetch, and events per second, with many
  syncs at once if asked, and fails when the relay names an event the client
  does not lack, misses one it does, or returns one altered. It runs against
  strfry 1.1.3, Wok 0.7.0 and Wok master.
- CI runs `scripts/attack-surface-reach.py --check` (`reachability.yml`) on
  changes to the crates, the script or the toolchain, so a pull request that
  makes a relay function newly reachable, before authentication or after,
  fails until its baseline in `crates/wok-compat/tests/reachability/` is
  rewritten with the reason (#156).
- `relay.search_enabled` turns NIP-50 search off (#153). Search was served
  and advertised in every configuration, so its query parser and ranked scan
  were reachable even in the `minimal` attack-surface profile, which turns
  off every capability a setting can. Off, NIP-11 no longer lists NIP-50, and
  a REQ or COUNT whose filters carry `search` gets `CLOSED`
  `blocked: bad req: search disabled`, a NEG-OPEN `NEG-ERR`
  `blocked: search disabled`, before any filter is parsed; each is counted
  by `wok_refusals_total{setting="relay.search_enabled"}`. It defaults to
  `true`, reloads live, is on the dashboard, and turning it on or off is
  logged as a security-scope change. Subscriptions already open keep their
  search filters until they close, and the search index stays current, so
  turning search back on answers from a complete index.
- `wok doctor` has a `config-public-values` check under any preset but
  `public` (#97). It names each setting the file pins to the `public`
  preset's value where its own preset gives another. A copy of the 0.7
  `docs/wok.toml` with `preset = "marmot"` kept 1 MiB events, 2 MiB
  WebSocket messages and Unix frames, COUNT, permessage-deflate and
  `relay.abuse.event_burst = 100` without a word: none of those is a past
  default, so `config-defaults` passed them, and `wok config minimize` keeps
  them because they differ from `marmot`'s.
- Wok warns when a message cap is too small for the limits behind it (#97
  §2.2): `relay.max_websocket_payload_size`, or `relay.unix.max_frame_bytes`
  while the Unix socket is on, smaller than `events.max_event_size` plus
  `["EVENT",]`'s 10 bytes, or than `relay.max_req_filter_size` plus a REQ's
  12 (a COUNT's 14 while COUNT is on). Such an event, REQ or COUNT passed its
  own limit but was cut off, and its connection closed (WebSocket 1009), with
  no `OK` or `CLOSED` and nothing in the logs, as with
  `events.max_event_size = 4194304` under the `public` preset's 2 MiB cap.
  The warning is logged at startup and on reload (the caps apply at restart,
  the limits live), shown beside the fields on the dashboard, and reported by
  a new `message-caps` check in `wok doctor`.
- Operator documentation in the dashboard's order (#97 §5). `docs/config.md`
  now runs preset, access, events accepted, queries, rates, storage, sync,
  relay information and advanced, then the restart-only infrastructure, and
  says for each limit what it protects, what breaks when it is set too low,
  and the NIP-11 field that advertises it. The keys that 0.7 files may still
  set are gathered under "Files from 0.7 and earlier", and the limits that are
  not settings are listed. `docs/presets/public.md` and `marmot.md` say who
  each preset is for, what it changes and what it deliberately refuses.
  Tests hold each documented default to the code and each preset page to the
  keys its overlay sets.
- The operator dashboard explains the relay it configures (#97 §5.1). A
  posture card at the top names the preset and what it is for, counts the
  settings the config file overrides, says in a few sentences who can read
  and write and which kinds are private, and warns when the file on disk
  cannot be served. The access settings are shown read-only first, with what
  each policy and read class means. The other settings follow in operator
  order (events accepted, queries, rates, storage, sync, relay information,
  advanced), each with what it does and what breaks when it is set too low or
  too high. Sizes and durations take units (KiB to GiB, seconds to years),
  limits that zero turns off have an **Off** switch, and a token bucket's
  rate and burst sit together. The dashboard can now also edit
  `relay.filter_validation.require_scoped_filters`, the
  `[relay.abuse.per_connection]` budgets, `relay.abuse.ipv6_prefix_len`, and
  the sync memory budgets and idle timeout, and shows the client address
  header (`relay.real_ip_header`), the largest message, the disk reserve and
  the database size limit read-only.
- The dashboard shows each setting's place against its preset and NIP-11,
  and what it refused (#97 §5.1 items 3–5). A setting the file overrides is
  marked, with the preset's value and **Reset to preset**. A value NIP-11
  advertises carries a `NIP-11: <field>` chip, shown only while it is
  advertised. Each field shows what its setting refused over the last 24
  hours, from `wok_refusals_total`, and the posture card sums them and names
  the settings that refused most. A guard the file sets to zero, while its
  preset does not, shows the reload warning beside it. **Changed:** the
  dashboard's **Rejected** tile, which counted only events superseded or
  deleted on write, is now **Refused**, every refusal over the last 24
  hours.
- `wok_refusals_total{setting}`, one counter of refused requests and
  events, labelled by the config key that refused them, such as
  `relay.abuse.per_connection.req_burst` or `events.max_num_tags` (#97
  §5.1). A token bucket's refusals carry its `_burst` key. Refusals that had
  no counter are now counted too: event validation (`created_at` bounds,
  size, tags), filter limits (`max_filters_per_req`, `max_req_filter_size`,
  `max_tags_per_filter`, `max_and_entries`), each `filter_validation` rule,
  `accepted_kinds`, the read classes, the read and write policies, the
  per-connection filter and subscription caps, the write-policy plugin, and
  sync's memory and size budgets. Refusals no setting makes, such as a
  NIP-86 ban or AUTH's fixed timestamp window, are not. **Deprecated:**
  `wok_abuse_rejections_total{reason}` still counts as before for this
  release and will be removed in the next; `docs/observability.md` maps
  each `reason` to its settings.
- The `marmot` preset, for a relay dedicated to Marmot group messaging
  (`preset = "marmot"`): only the Marmot kinds, scoped filters, 4 MiB events,
  room for an inviter's Welcome burst and a NIP-77 pass per group, and open
  writes so group membership stays unlinkable at the relay. It refuses to
  start without `relay.auth.service_url`, and a reload or a dashboard or
  NIP-86 save that would remove it is refused. See `docs/config.md`,
  The `marmot` preset (#97 §4.2).
- `relay.auth.accepted_kinds`, the kinds a relay accepts (empty, the
  default, accepts every kind). Events of other kinds are refused with
  `restricted: kind N is not allowed by this relay`, and NIP-11 advertises
  `restricted_writes`. It bounds the NIP-86 kind policy: `disallowkind`
  narrows it, `allowkind` cannot widen it (it can still lift a kind's ban on
  stored events), and `listallowedkinds` reports the effective set instead
  of only the kinds named by `allowkind` (#97 B14). NIP-62 vanish requests
  are accepted whatever it lists, and stored events of other kinds stay
  readable.
- NIP-11 `limitation.auth_required` (`true` while `relay.auth.read_policy`
  is not `open` and AUTH is usable), `restricted_writes` (`true` while `write_policy` is not
  `open`, or proof of work is required) and `max_subid_length` (64) (#97
  B12).
- `relay.filter_validation.require_scoped_filters`: every filter must name
  `ids`, `authors` or a tag filter, with any number of values. It refuses
  enumeration such as `{"kinds":[445]}`, which would list every group message
  on a Marmot relay, and accepts the `#h`, `#p`, `ids` and directory filters
  Marmot clients send, which `require_author_or_tag` refuses (#97 F13).
- `relay.auth.read_policy` and `relay.auth.write_policy`, each `open` (the
  default), `authenticated` or `members`, and `relay.auth.inbox_kinds`.
  A member is a pubkey that is not banned and is allowlisted, holds a role or
  is in `admin.pubkeys`. A REQ, COUNT, NEG-OPEN or EVENT the policy refuses
  gets `auth-required:` and a challenge while authenticating could help, and
  `restricted:` otherwise. A connection the read policy stops admitting,
  such as a removed member, or an anonymous one after a reload to
  `authenticated`, gets nothing more on its subscriptions: a scan waiting or
  running is refused with CLOSED at its next time slice, and its sync
  sessions close. A reload that changes either
  policy is logged as a warning naming the old and new policy, and `wok
  doctor`'s `relay-auth` check, like the startup warning, now also names a
  policy that needs AUTH while AUTH is unavailable. See `docs/config.md`,
  Read and write policies.
- Read classes in `[relay.auth]`: `recipient_only_kinds` (default
  `[4, 1059, 21059]`, the author and first `p`-tag recipient),
  `owner_only_kinds` (default `[78, 30078]`, the author alone) and
  `authenticated_kinds` (default empty, any authenticated connection). A kind
  in several classes gets the strictest. See `docs/config.md`, Read classes.
- A `(tag, kind, created_at)` index, the LMDB table `wok_Event__tagKind`, for
  filters that combine one single-letter tag with `kinds`: DM inboxes
  (`{"#p":[me],"kinds":[1059]}`), zaps, reactions to a note, `#a` filters.
  Once the index is complete, such a filter reads only the events of the
  requested kinds from it, instead of the tag value's whole history, and
  still checks each against its stored event, so it returns the same events.
  At 5M events, the top pubkey's DM inbox (limit 500) takes 0.95 ms warm and
  0.14 s cold instead of 9.1 ms and 1.07 s, and a busy pubkey's zaps 0.9 ms
  and 0.24 s instead of 7.7 ms and 2.1 s. Shapes where most of the value's
  events match, such as notifications, are unchanged. The writer keeps an entry for every
  single-letter tag of every event it stores, so the database grows by about
  14% once every event is indexed, and writes take about 18% longer
  (measured at 5M events). `wok import` into a new database, or one whose
  index is not built yet, leaves the entries out and builds the index in key
  order once its events are written, as the relay builds it for an upgraded
  database, so the index is complete when the import exits. A million events
  of a social relay's history took 368 s and left a 6.4 GB file, the size
  without the index, against 496 s and 8.0 GB when the import kept it event
  by event. It builds in the relay's bounded steps. While another process
  has the database open, as a running relay does, batches keep the index as
  they go and the import leaves any build to the relay, which would
  otherwise begin it under the load. An import stopped before it builds the
  index leaves it for the relay to finish. A new database is complete from
  its first open, and again once an import into it ends.
  On the first start after the upgrade, and after a strfry migration, the
  relay builds the index for the stored events in the background, without
  delaying startup: a key-ordered pass over the tag index, in steps of at
  most 10 ms of indexing between writer batches, resumed after a restart.
  It pauses while free disk space is below `database.min_free_disk_bytes`.
  A 1M-event database took about 13 s and wrote about 3 GB to disk, and
  publication acknowledgements stayed within a few milliseconds of their
  usual latency. Progress is logged every 10 s and exported as
  `wok_tag_kind_index_*` and `wok_tag_kind_backfill_*` metrics.
  `wok reindex --confirm-relay-stopped` builds the index offline instead.
  The database version stays 5, and earlier releases ignore the tables:
  events they insert are indexed in the background once this release runs
  again, and the entries of events they delete stay behind until a reindex.
  `wok integrity` reports the table under `tag_kind_index`, and `wok doctor`
  adds a `tag-kind-index` check: those leftover entries and a build in
  progress are warnings, and entries missing below the index's progress
  marker are a failure.
- `relay.max_filter_bytes_per_connection` (default 2097152, 2 MiB) bounds the
  filter bytes of the REQ subscriptions open on one connection. Live filters
  stay in memory until closed, so without it a larger
  `relay.max_req_filter_size` multiplied the memory one connection can hold
  (200 subscriptions of 256 KiB is 50 MiB). A REQ over the budget gets
  `CLOSED` with `blocked: this connection's filters exceed <budget> bytes`.
  Reusing an open subscription ID is charged only for the difference, and
  COUNT is not charged. Zero is unlimited and is warned about on reload. The
  setting reloads live and is in the dashboard.
- NIP-67 EOSE completeness hints, advertised in NIP-11. EOSE gains a third
  element when Wok knows the answer: `finish` when every stored match the
  connection may read was sent, `more` when a filter's `limit`, the
  `relay.max_filter_limit` clamp or `relay.max_total_events_per_req` left at
  least one, and `auth` when the restricted-read rule hid stored matches from
  an unauthenticated connection while AUTH is usable. A REQ admitted after a
  reload made AUTH usable now gets the connection's challenge first, as the
  hint requires. Each filter a limit cuts costs a bounded peek for one more
  match; when the peek cannot tell, EOSE has no `finish` or `more`. Clients
  that index EOSE by position are unaffected; a client that requires exactly
  two elements must accept three.
- `wok-bench --scenario ws_transport` measures what WebSocket connections
  cost the relay, with and without permessage-deflate: RSS per open, warm and
  idle connection, history bursts, live fan-out, reconnect churn, and the
  deflate codec at each level.
- Configuration presets. The optional top-level key `preset` selects a named
  set of defaults; configuration resolves as built-in defaults, then the
  preset's overlay, then the file. `public`, the built-in defaults, is the
  only preset and is selected when the key is absent, so no default changes.
  Unknown preset names are rejected. `wok config show` prints the effective
  configuration with each value's origin (default, preset, or file and line),
  and `--overrides` prints only the keys the file changes from its preset.
  Files written by `wok migrate strfry` now include `preset = "public"`, and
  dashboard saves keep a file's `preset`.
- `wok config minimize` removes the settings a config file sets to its
  preset's value, keeping comments, so the relay follows the preset when a
  default changes. The effective configuration is unchanged. It keeps the
  original as `<file>.bak`; `--dry-run` prints a unified diff instead.
  `wok config show --defaults` lists every setting with the preset's value.
- `wok doctor` has a `config-defaults` check. It warns about settings pinned
  to a default an earlier release used and the preset has since replaced,
  such as `events.reject_older_than_secs = 94608000` and
  `relay.auth.restricted_read_kinds = [4, 1059]` from a copy of the 0.7
  `docs/wok.toml`, and counts the settings `wok config minimize` would
  remove.
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

- `relay.real_ip_header = "forwarded"` reads the RFC 7239 `Forwarded`
  header (#155): the client is the `for` of its last element, quoted or not,
  an IPv4 address with or without a port, or an IPv6 address in brackets.
  Behind a proxy that writes `Forwarded`, such as HAProxy's
  `option forwarded`, every client had the proxy's address and shared its
  per-address budgets, NIP-86 IP blocks could not single one out, and each
  request was counted in `wok_real_ip_header_unparsed_total`. The syntax
  follows from the header's name; any other header is still an address
  list. The last element is found from the right, so nothing a client sends
  ahead of it moves it. One that names no address, such as `for=unknown` or
  an obfuscated `for=_hidden`, still leaves the connecting address and is
  counted. The ingress fuzz target covers both syntaxes.
- `relay.trusted_proxies` lists the proxies in front of the relay, as
  addresses or CIDR ranges (#155). Behind a CDN and then nginx, the last
  entry of `relay.real_ip_header` is the CDN edge's address, so every client
  of that edge shared one set of per-address budgets and NIP-86 `blockip`
  could not single one out. With the proxies listed, Wok skips their
  addresses from the header's end, and the first address outside them is the
  client. A connection from outside them is its own address and its header
  is ignored, so a client that reaches the relay directly can no longer name
  another address. Empty, the default, keeps the header's last entry from any
  connection. A range of every address is refused, the startup warning names
  the ranges, and a reload that changes them or `relay.real_ip_header` is now
  logged as a security-scope change.
- NIP-86 `unbanevent`, `unallowevent`, `listallowedevents` and
  `listdisallowedkinds`, from the current NIP-86 draft. `allowevent` also
  puts the event on an allow list, with its optional reason, which
  `listallowedevents` returns; the allow list records the approval and
  changes no visibility. The NIP-43 claim methods are not implemented.
- `docs/attack-surface.md` lists every entry point: each HTTP path, client
  message, NIP-86 level, Unix-socket check and `wok` command, who can reach
  it, the setting that gates it, and the work Wok does before that gate.
  Tests fail when the listener answers a path the page does not list, in any
  of seven configuration profiles, or when a client verb, NIP-86 method level
  or command differs from it. `docs/nip86.md` now gives each method's level.
- The ingress fuzz target covers the context-takeover inflater that browsers
  negotiate (#166): compressed WebSocket messages that refer back into
  earlier ones, and messages after the idle decompressor is released, which
  replay up to 32 KiB of history into a new one. It covered only the
  inflater without takeover before.

### Preset changes

- `marmot` (new): over the public preset, `relay.auth.accepted_kinds =
  [0, 3, 5, 62, 445, 1059, 10000, 10002, 10050, 30443]`,
  `relay.filter_validation.require_scoped_filters = true`,
  `events.max_event_size = 4194304`, `relay.max_websocket_payload_size` and
  `relay.unix.max_frame_bytes = 8388608`, `relay.max_filter_limit = 5000`,
  `relay.abuse.event_burst = 300`, and `[relay.abuse.per_connection]`
  `req_rate_per_second = 50`, `req_burst = 300`, `neg_msg_burst = 500`.
  COUNT (NIP-45) and permessage-deflate are off,
  `relay.max_filter_limit_count = 0` and `relay.compression_enabled = false`,
  since MDK never sends COUNT or offers compression (#166): a COUNT is
  refused with `blocked: bad req: COUNT disabled`, NIP-11 does not list
  NIP-45, and a client that offers deflate gets an uncompressed connection.
  NIP-77 is sized to MDK's syncs (#166): `relay.max_sync_events = 65536`
  and `relay.sync_memory_per_connection = 134217728` (128 MiB). Each MDK
  session names one group or inbox with `limit` 16,385, about 8 MiB of sync
  memory, and MDK runs at most eight at once per relay connection, so a
  connection holds 15. A session without a `limit` reserves 20 MiB, not
  248 MiB, and is refused past 65,536 events with `blocked: too many query
  results`. `relay.sync_memory_total` stays 1 GiB.
- `public`: `relay.nodeinfo_enabled` is `false` (new), so NodeInfo is not
  served (see Security).
- `public`: `relay.auth.owner_only_kinds` is `[78, 30078]` (new), so NIP-78
  app data is read and published only by its author (see Security). Apps
  that publish public data in these kinds can no longer be read by other
  users; set `owner_only_kinds = []` to serve them as before.
- `public`: `events.reject_older_than_secs` is `0`, no lower bound on
  `created_at` (was 94608000, three years), and NIP-11 omits
  `created_at_lower_limit`. A 2020 profile, follow list or deletion can be
  rebroadcast again. Files that pin the old value, as copies of the 0.7
  `docs/wok.toml` do, keep the bound, but it now spares the kinds listed
  under Changed.
- `public`: `relay.max_req_filter_size` is `262144`, 256 KiB of filters per
  REQ or COUNT (was 65536). An outbox client's REQ for a follow list of
  2,000 authors is accepted; 64 KiB refused one of about 970 authors or
  more. One filter still lists at most 2,047 authors. Files that pin 65536,
  as copies of the 0.7 `docs/wok.toml` do, keep the old cap, and `wok
  doctor` flags them.
- `public`: result sizes, all advertised in NIP-11 `limitation`. Files that
  pin the old values, as copies of the 0.7 `docs/wok.toml` do, keep them,
  and `wok doctor` flags them.
  - `relay.max_filter_limit` is `2000` (was 500), and so are `max_limit` and
    `default_limit`. MDK's directory batches (`limit` 1,200) and outbox
    metadata fetches without a `limit` are no longer cut at 500.
  - `relay.max_total_events_per_req` is `10000` (was 2000), so a merged
    batch of filters is no longer cut at 2,000 events in all.
  - `relay.max_tags_per_filter` is `8` (was 3), so NIP-22 comment queries on
    `#E`, `#K`, `#P` and `#k`, and other filters with four or more tag
    letters, are accepted.
  - `events.max_num_tags` is `5000` (was 2000), NIP-11 `max_event_tags`, so
    heavy users' follow and mute lists are accepted.
- `public`: storage quotas. Files that pin the old values, as copies of the
  0.7 `docs/wok.toml` do, keep them, and `wok doctor` flags them.
  - `relay.abuse.max_stored_events` is `0`, no global event cap (was
    10000000). At the cap every write on the relay failed, and a busy public
    relay stores far more. `database.map_size` and
    `database.min_free_disk_bytes` bound storage.
  - `relay.abuse.max_stored_events_per_pubkey` is `1000000` (was 100000),
    so active users and bots keep posting.
- `public`: `relay.filter_validation.max_kinds_per_filter` is `0`, no limit
  (was 3), now that the section has no `enabled` switch. Otherwise the
  switch's removal would have turned on a three-kind cap that refuses MDK's
  six-kind directory batches.
- `public`: `relay.abuse.max_query_work` is `20000`, NIP-11
  `max_query_work`, in the units described under Changed. It replaces
  `relay.abuse.max_query_cost = 1000`, which is ignored (see Removed).
- `public`: `relay.message_read_timeout_secs` is `120`, a new setting: a
  WebSocket message or control frame must arrive within 120 seconds of its
  first byte (see Security). `0` turns the deadline off.
- `public`: `relay.abuse.max_connections_per_address` is `256`, a new
  setting: an address may hold at most 256 WebSocket connections open at
  once (see Security). Behind a reverse proxy, set `relay.real_ip_header`,
  or every client shares the proxy's 256. `0` removes the cap.
- `public`: `relay.abuse.ipv6_prefix_len` is `64`, a new setting.
  Per-address budgets (connections, EVENT and AUTH, REQ, COUNT, malformed
  messages) key an IPv6 client by its /64 instead of its full address, so a
  host can no longer take a fresh budget with each address it picks from its
  network. `128` keys each IPv6 address on its own, as before. IPv4 is
  unchanged, and NIP-86 IP bans still match exact addresses.
- `public`: REQ and COUNT budgets are per connection first, with the
  per-address keys as a backstop (see Changed). Files that pin the old
  per-address values, as copies of the 0.7 `docs/wok.toml` do, keep them as
  their backstop, and `wok doctor` flags them.
  - New `[relay.abuse.per_connection]`: `req_rate_per_second = 20` and
    `req_burst = 100` (REQs, replacement REQs and NEG-OPENs; a 60-REQ
    startup fits), `neg_msg_rate_per_second = 50` and `neg_msg_burst = 200`,
    `count_rate_per_second = 5` and `count_burst = 20`, and
    `authenticated_multiplier = 4`.
  - `relay.abuse.req_rate_per_second` is `200` and `req_burst` `1000` (were
    20 and 40, the only REQ budget, per address).
  - `relay.abuse.count_rate_per_second` is `20` and `count_burst` `50` (were
    5 and 10).

### Changed

- Opening a database no longer fails when the search index is being rebuilt
  and an event has no payload, or a payload that does not decode (#257).
  The event is left out of the index, and `wok doctor` reports it.
- NIP-50 search covers only kinds whose content is text a person wrote, such
  as notes, articles, comments and chat, plus profiles (#257). It matched
  any kind whose `content` held the words, so a search without `kinds`
  returned reposts, whose embedded JSON repeats the original, and random
  fragments of encrypted messages, and every such event wrote postings. A
  profile is now searched by its name, display name, NIP-05 and about
  rather than its raw JSON, so "https" no longer matches every profile with
  a picture, and the title, subject, name, summary and description tags of
  articles and other text kinds are searched with their content. A live
  event matches by the same first 256 words the index keeps. The list is in
  [NIP-50 search](docs/nip50-search.md); the index is rebuilt on the first
  open.
- The NIP-50 search index keeps only word postings (#257). It also kept a
  posting for each pair of adjacent words, up to 256 an event, which only
  boosted a match whose content holds the query's words in order; that
  boost is now read from a match's content when it is ranked. A published
  event writes about half as many postings, and a phrase late in a long
  event, past the old 256 pairs, now counts. The index is rebuilt on the
  first open, in 10,000-event transactions before the relay serves.
- `[relay.filter_validation]` rules now apply to NEG-OPEN as they do to REQ
  and COUNT, refused with `NEG-ERR blocked: filter validation failed: ...`.
  Before, a sync could list the ids of every event a REQ's filter was
  refused for.
- A REQ, COUNT or NEG-OPEN over `relay.abuse.max_concurrent_historical_queries`
  (8) waits for one of its connection's running scans to end, in arrival
  order, instead of being refused. Before, a startup burst on a busy relay
  lost every scan past the eighth, `CLOSED rate-limited: too many concurrent
  historical queries` (or a NEG-ERR, `blocked: synchronization query
  unavailable`), even within its rate budget. At most
  `relay.max_subs_per_connection` queries wait per connection; past that a
  REQ or COUNT is refused with `rate-limited: too many historical queries
  waiting on this connection`. A CLOSE or a replacing REQ removes a waiting
  query, so it never answers (#97 F2). Since a waiting COUNT holds its
  filters, `relay.max_filter_bytes_per_connection` now also bounds a
  connection's unanswered COUNTs, separately from its REQs.
- REQ, COUNT, NEG-OPEN and NEG-MSG are charged to a budget of the
  connection's own (`[relay.abuse.per_connection]`) and to its address's
  backstop (`relay.abuse.req_*`, `count_*`), and are refused when either is
  spent. Before, the only REQ budget was 20 a second, burst 40, per address,
  so a client opening 60 subscriptions at startup lost 20 of them, and users
  behind one NAT, office or VPN shared that budget. The connection is
  charged only when its address's backstop admits too. Refusals by the
  backstop end `for this address`; both keep `rate-limited:`.
- NEG-MSG rounds no longer cost REQ tokens. They draw on a per-connection
  NEG-MSG budget, and on the address's REQ backstop, so a client that runs a
  NIP-77 pass per group at startup still has its REQ budget for the
  subscriptions it opens next. A NEG-OPEN still costs a REQ token.
- Authenticating raises a connection's own REQ, NEG-MSG and COUNT budgets
  by `authenticated_multiplier` (4), at once. Before, an AUTHed connection
  was also charged to a per-pubkey REQ and COUNT bucket at the per-address
  rate, so AUTH made the budget stricter and every connection signed in
  with one key shared it. Those buckets are gone. The per-address backstop
  is not multiplied, since any key can authenticate on an open relay.
- `wok relay` warns at startup when `relay.real_ip_header` is empty and the
  relay listens only on loopback or private addresses, as behind a reverse
  proxy: every client then has the proxy's address and shares one set of
  per-address budgets. The warning logged when the header is set now says to
  set it only when every connection comes from a proxy that overwrites it.
- Reload warns about a guard set to zero (unlimited) only when the file's
  preset does not set it to zero too. Before, every zero warned, so the
  public preset's `relay.abuse.max_stored_events = 0` would have been warned
  about on every reload.
- Dashboard saves and the NIP-86 relay-info methods edit `wok.toml` in place.
  They change only the settings whose value changed, remove a setting set
  back to its preset's value, and keep comments and layout. Before, a save
  rewrote the whole file with every setting, which dropped comments and
  pinned every default. A save now applies the form to the file on disk
  rather than to the running configuration, so it no longer reverts a
  restart-only setting changed in the file since startup, and refuses a file
  that does not parse instead of overwriting it.
- `docs/wok.toml` is a short annotated sample that selects the preset and
  shows, commented out, the settings a relay must or commonly should set,
  such as `relay.auth.service_url`. The full list of settings is in
  `docs/config.md` and `wok config show --defaults`.
- WebSocket connections cost less memory and CPU. permessage-deflate state
  (about 300 KiB per connection) is allocated by a connection's first message
  instead of at upgrade, and released after 30–60 s without traffic. The read
  buffer shrinks back to 1 KiB between messages. Outbound frames already
  queued go out in one write instead of one write each. Outbound compression
  uses level 1, as strfry does, instead of 6: less than half the CPU, for
  about 15% more bytes on kind-1 history (4–15% depending on kind). A new
  connection no longer waits up to a millisecond for a timer tick before it
  reads its first message, which roughly triples reconnect throughput.
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
- The req monitor's live-subscription index is cheaper under churn. CLOSE,
  REQ replacement and disconnects now take time in proportion to the
  subscription's own filter keys. Before, they scanned every subscription that
  shared those keys, so a 500-author feed over popular authors was slow to
  remove and reconnect storms grew quadratically. Matching an event no longer
  allocates per tag or per candidate, and it skips filters that cannot take
  the event's kind.
- Frames for different connections are queued under per-connection locks
  instead of one relay-wide lock, so live fan-out to many connections no
  longer serializes on it.
- A REQ queued behind CLOSEs, AUTH or disconnects no longer waits a query time
  slice for each of them while other queries run. The req worker now takes
  everything queued in one pass, and starts each new REQ or COUNT as it takes
  it. While new REQs keep coming, running queries still get a slice after
  each stretch of new work as long as their last slice.
- Live delivery does less work per event: the writer hands each commit's
  events to the req monitors instead of each monitor reading them back.
- History scans, COUNT and live delivery check read visibility more cheaply.
  Each event used to cost a vanish lookup, three moderation lookups, a
  replacement lookup for replaceable kinds and a clock read. Now the clock and
  which of those tables hold records are read once per scan slice or live
  batch, and an event is looked up only where a record could hide it. With no
  moderation or vanish records, a scan does about a quarter less work per
  event.

- The query-cost gate (`relay.abuse.max_query_work`, which replaces
  `max_query_cost`) estimates the index entries a REQ, COUNT or NEG-OPEN
  would touch, on the plan its scan will run. A REQ costs the cursors its plan opens plus the rows its filters'
  `limit`s allow, up to `max_total_events_per_req`. A COUNT costs twice its
  cursors and a NEG-OPEN its cursors, because their rows are bounded only
  while they run. Before, the estimate ignored `limit` and the plan. It
  refused `{"authors":[150 keys],"limit":20}` (1,500), an 11-kind feed
  (1,100) and NDK's 45 `{"#e":[id],"kinds":[7]}` filters (1,125), while
  `{"authors":[2000 keys],"kinds":[50 kinds]}` cost 5 and opened 100,000
  cursors. Those now cost 170, 61, 10,045 and 102,000, against a ceiling of
  20,000. `docs/config.md` lists how each filter is priced.
- `wok import` parses and verifies the next batch on a thread of its own
  while it writes the current one, as strfry does, instead of between write
  transactions. Importing a million events of a social relay's history took
  489 s instead of 555 s on a 48-vCPU host, and 273 s instead of 334 s with
  `--write-batch 100000`. The same transactions write the database.

### Removed

- `relay.auth.restrict_writes`. A file that still sets it loads with a
  deprecation warning, at startup, on reload and in `wok doctor`, and `wok
  config minimize` or a dashboard save rewrites it: `true` becomes
  `write_policy = "members"` (see Security for what that also admits), and
  `false` is dropped.
- `relay.auth.restricted_read_kinds` and
  `relay.auth.restrict_read_to_involved_pubkey`. A file that still sets them
  loads with a deprecation warning, at startup, on reload and in `wok
  doctor`, and `wok config minimize` or a dashboard save rewrites it:
  `restricted_read_kinds` becomes `recipient_only_kinds` with the same
  meaning, and `restrict_read_to_involved_pubkey = true` is dropped.
  `restrict_read_to_involved_pubkey = false` let a REQ that mixed in another
  kind read the restricted kinds without AUTH; its kinds become
  `authenticated_kinds`, which any authenticated connection may read and no
  other can. `wok migrate strfry` translates strfry's keys the same way.
- `relay.abuse.max_query_cost`. `relay.abuse.max_query_work` replaces it,
  in units in which old values mean something else: 1,000, the default
  through 0.7, would refuse every filter without a `limit`, including MDK's
  `{"kinds":[445],"#h":[group]}` subscriptions and DM inboxes. A file that
  still sets `max_query_cost` loads with any value ignored and a
  deprecation warning, at startup, on reload and in `wok doctor`'s
  `config-deprecations` check, and gets the preset's `max_query_work`.
  **Upgrading:** copies of the 0.7 `docs/wok.toml` set it, so they warn
  until it is removed; `wok config minimize` or a dashboard save removes it.
  An operator who had raised or lowered it should set `max_query_work`
  instead, choosing a value in the new units (`docs/config.md`, Query
  work). NIP-11 advertises `max_query_work` in place of `max_query_cost`.
- `relay.filter_validation.enabled`, `max_filters_per_req` and
  `min_filters_per_req`. Each remaining filter rule (`max_kinds_per_filter`,
  `allowed_kinds`, `require_author_or_tag`) applies when it is set, and
  `relay.max_filters_per_req` alone bounds the filters in a REQ. A file that
  still sets the old keys loads with a deprecation warning, at startup, on
  reload and in `wok doctor`'s new `config-deprecations` check, and keeps
  the rules it had:
  - `enabled = false`, as in copies of the 0.7 `docs/wok.toml`: the
    section's rules are ignored, as before.
  - `enabled = true`: its rules still apply, with 0.7's default of 3 for a
    `max_kinds_per_filter` it leaves out. Its `max_filters_per_req` (or the
    old default, 3) becomes `relay.max_filters_per_req` when that is
    lower, so such a REQ is now refused with `invalid: bad req: arr too big`
    instead of `filter validation failed: invalid number of filters`.
    `min_filters_per_req` is dropped with a warning, because nothing
    equivalent remains and a REQ needs only one filter.
    `max_kinds_per_filter = 0`, which refused every filter that lists kinds,
    now means no limit, so those filters are accepted; a dedicated warning
    at startup and in `wok doctor` says so and points to `allowed_kinds`.
    These three choices are the owner's (#97): upgrades never fail on the
    old keys.
  - No `enabled`: the section is read as a current one, so each rule it
    sets applies. Under 0.7 such a section was off.

  `wok config minimize` and dashboard saves rewrite the section that way, and
  `wok migrate strfry` translates strfry's `relay.filterValidation` the same
  way. The dashboard no longer shows the three fields.
- Dated benchmark, soak, lab and audit reports, the definition-of-done report
  and `PLAN.md` are no longer kept in the repository or shipped in release
  archives. `docs/` now holds only design, policy, operations and benchmark
  methodology; results belong in pull requests.

### Fixed

- A NIP-59 gift wrap to a pubkey that sent a NIP-62 vanish request is
  refused, hidden and deleted only when it is dated at or before the
  request, as the pubkey's own events are (#249). Every wrap that p-tagged
  the pubkey was refused for good, so once a key vanished nobody could send
  it a DM through this relay again, though NIP-62 resets the key rather than
  retiring it. NIP-59 dates a wrap up to two days in the past, so **a wrap
  sent in the two days after a request can still be refused**. Wraps refused
  or deleted before this fix do not come back.
- A NIP-50 search finds the same events live as in history, COUNT and
  NEG-OPEN (#247). The search index keeps each event's first 256 unique
  terms, so that one event of many distinct words cannot amplify into
  thousands of index writes, but live matching used every word: a long
  article whose 300th distinct word was `zebra` reached a
  `{"search":"zebra"}` subscription open when it arrived, and the same
  search sent later never found it. **Live search no longer matches a word
  an event first uses after its 256th unique term**, and `wok sync` with a
  `search` filter checks the events it downloads the same way.
  docs/nip50-search.md now states the cap.
- `wok sync` with a NIP-91 `&` filter no longer fails against a peer that
  does not advertise NIP-91 (#250). Such a peer is sent each `&x` set folded
  into its `#x` clause, a superset of the filter, but the local side
  reconciled the exact filter, so each remote event of the superset outside
  it was a false `need`: it was downloaded, counted `rejected`, and the run
  exited `sync incomplete` every time, and `--check`, `--print-missing` and
  `--dir none` reported the same false differences. Sync now reconciles the
  superset on both sides and narrows the differences to the exact filter:
  local events outside it are not uploaded, remote ones are fetched and
  discarded, and both are counted in a new `narrowed` summary field instead
  of `have`, `need` or `rejected`. **With such a filter, `--check`,
  `--print-missing`, `--dir none` and `--dir up` now fetch the peer's
  remote-only events of the superset**, without storing them, since only an
  event shows its tags. The local view, and its `relay.max_sync_events` and
  sync memory budget, now cover the superset. **Sync now refuses an `&`
  filter with a `limit` for such a peer**, which would apply the limit to
  the superset; bound the sync with `--range` instead.
- A `#d` filter for the empty string matches only events with a `d` tag of
  that value, and addressable events without a `d` tag, whose address it is
  (#245). Packing adds an empty `d` to every replaceable and addressable
  event, so that the first `d` sets the address and a missing one means the
  empty string, and filters matched it: `{"kinds":[30023],"authors":[pk],
  "#d":[""],"limit":1}`, which resolves an `naddr` with an empty
  identifier, returned pk's newest article whatever its `d`, a live
  subscription to it got each new one, and `{"kinds":[10002],"#d":[""]}`
  matched every relay list. REQ, live subscriptions, COUNT, NIP-77 and
  NIP-91 `&d` now leave the added tag out. The tag indexes still hold it,
  so a filter for the empty `d` reads each candidate event instead of
  answering from the index alone. **Clients that relied on `#d:[""]`
  selecting every replaceable or addressable event get fewer events.** A
  persistent negentropy tree whose filter selects the empty `d` still holds
  the events the old matching put there: `wok doctor` reports it, and
  `wok reindex --confirm-relay-stopped` rebuilds it. A tag with no value,
  such as `["t"]`, is still packed and matched as `["t",""]`, and kind 41
  history that earlier releases packed as replaceable keeps its added `d`.
- `wok upload` exits nonzero unless the relay acknowledged every event it
  sent and refused none (#252). It counted any message that contained `"OK"`
  as an acknowledgment, `OK false` and a NOTICE included, and exited 0 when
  the connection dropped, so a relay that refused events, or rate-limited and
  disconnected partway through the input, left the operator believing the
  data was copied. It now matches each OK to an event it sent by id, logs
  each refusal with its reason, and prints a summary line on stderr like
  `wok sync`'s. It exits nonzero when the relay refused an event, or the
  connection closed with acknowledgments outstanding or input left unsent.
  A refusal because the relay stores a newer version counts as
  `superseded`, as in `wok sync`, and is not a failure. **A line that is not
  event JSON is no longer sent**: it is logged and the command exits
  nonzero, as `wok import` does. **`--pipeline 0`**, which sent nothing and
  exited 0, **is refused**.
- `wok scan` and `wok scan --count` read the whole database (#256). They
  clamped a filter to `relay.max_filter_limit`, which bounds client REQs, so
  at the default of 2000 `wok scan --count '{"kinds":[1]}'` printed 2000 on
  a database holding millions of notes, and `wok scan '{}'` stopped after
  2000 events without saying so. strfry's `scan` has no such cap, nor do
  `wok delete` and `wok dict`; a `limit` in the filter still applies.
  Operator scans (`wok scan`, `wok delete`, `wok dict`) now hand each event
  over as they find it, not once the scan is done, and remember only what a
  filter cut by its `limit`, or a `search`, sent: counting every event takes
  memory for the events sharing one `created_at`, not for every match. A
  `search` filter whose rarest term has more than 4,096 postings returned
  nothing to them; it now runs to the end.
- `wok download` no longer waits forever when the relay refuses its REQ
  (#251). It read until EOSE or a Close frame, so a relay that answered
  `["CLOSED","_","auth-required: …"]`, such as a Wok relay with
  `read_policy = "authenticated"`, or refused with a NOTICE, or stopped short
  of EOSE, held it open as long as the relay kept the socket up. A CLOSED
  for its subscription, or a NOTICE before the first event that starts with
  `error:` or a NIP-01 refusal prefix such as `restricted:`, now ends it
  nonzero with the relay's reason and the number of events printed; other
  NOTICEs are logged. A new `--timeout` (default 60 seconds, 0 disables),
  like `wok sync`'s, ends it nonzero after that long without the WebSocket
  handshake, an event or EOSE.
- A second copy of an event in one writer batch, as two connections or a
  client that retries can send, is answered as the first copy was (#255).
  When the first copy was refused, as superseded by a newer version, over
  the author's storage quota, or deleted or vanished, the second was told
  `true, "duplicate: have this event"` though the relay did not hold the
  event, so its client stopped retrying. It now gets the same refusal, and
  `duplicate:` only when the first copy was stored. A copy of a vanish
  request that a relay at its global storage quota still stores is
  answered `duplicate:` too, not with the quota's refusal. The relay's
  metrics, `wok import` and `wok sync` count a refused copy with the
  refusals, not as a duplicate.
- permessage-deflate is negotiated as RFC 7692 §7 says (#246). The relay
  answered plain `permessage-deflate` to any offer and kept its compression
  context between messages, so a client that offered
  `server_no_context_takeover` or a `server_max_window_bits` below 15
  either refused the handshake, as Python `websockets` does, or failed to
  inflate from about its second message. The relay now accepts the first
  offer in the client's list it can honour: it echoes
  `server_no_context_takeover` and compresses each of that connection's
  messages on its own, echoes `server_max_window_bits=15`, still echoes
  `client_no_context_takeover`, and accepts `client_max_window_bits`.
  **An offer with an unknown, repeated or invalid parameter, or a
  `server_max_window_bits` below 15, is declined**, and a connection with
  no offer left is not compressed. Browsers, which offer only
  `client_max_window_bits`, negotiate as before.
- `wok router` no longer drops up-direction events when a peer's queue is
  full (#244). Each connection queued at most 256 events, and the rest of a
  burst, such as the up to 1,000 events a `both` stream downloads in one
  batch, or a `wok import` into a routed database, was dropped without a
  word. A stream now waits at the first event a connected peer has no room
  for and resumes there as that peer catches up. **A slow peer now holds
  back the other peers in its stream**, and a peer that takes longer than
  `connectionTimeout` to accept a frame is disconnected, with a log line,
  and reconnected. Up streams stay live-only: like any peer that
  disconnects, it misses the events queued for it, and `wok sync` repairs
  the gap. A reload that removes a URL, or changes a stream's `dir` or `filter`, now
  closes the connection even when its queue is full; before, the close
  waited in that queue, was lost when it was full, and left the old
  connection running and storing what it downloaded.
- A negentropy tree whose filter names more tag letters than
  `relay.max_tags_per_filter` no longer makes every write fail (#243). The
  writer parsed stored tree filters with that client-filter limit, so
  lowering it, or a `wok negentropy add` of a filter with 9 or more tag
  letters at the default of 8, refused every EVENT with `error: too many
  tags in filter` and aborted every maintenance tick, stopping NIP-40 expiry
  and NIP-62 sweeps. Stored trees now parse without the client-filter
  limits, as `wok doctor` already checked them, and `wok negentropy add`
  checks a new filter with that same parser. **It now refuses an array of
  filters**, which it stored before though every write then failed on it.
- NIP-77 reconciliation accepts a message whatever number of ranges it
  holds (#242). One with more than 4096 was refused, though the relay itself
  answers with 500,000-byte frames, which hold about 23,000: `wok sync`
  failed with `negentropy message has too many bounds` against Wok or strfry
  once the two sets differed by more than a few thousand events, and the
  relay sent `NEG-ERR "error: invalid reconciliation message"` to a client
  that used large frames. Storage work bounds a round instead: once its
  lookups and fingerprints have cost 65,536 B-tree descents, the reply
  answers the rest of its range with one fingerprint, as it does when it
  fills its frame, and the peer splits that range in its next message. A
  crafted message costs no more than the range cap let one cost (#254).
- A NEG-MSG sent before the relay replied to its session's NEG-OPEN, while
  the view built in memory is still being scanned, gets `invalid: NEG-MSG
  sent before the reply to NEG-OPEN`, and the session and its scan close
  (#222). NIP-77 has the client and relay take turns, so the message
  answers nothing. **Clients see a new reason**: it got `closed: unknown
  subscription handle`, which named the wrong cause.
- A NEG-MSG to a session served from a negentropy tree that no longer
  proves public what it holds gets `closed: visibility changed; reopen
  synchronization`, the reason a visibility sweep gives, and the session
  closes (#222). An event stored after the session opened, such as one of a
  restricted kind or one that expires, ends that proof. **Clients see a new
  reason**: such a NEG-MSG got `closed: unknown subscription handle`, which
  named the wrong cause and did not say to reopen. A check that fails to
  read the database gets `error: synchronization visibility check failed`.
- A NEG-OPEN or NEG-MSG whose negentropy message does not reconcile gets one
  `NEG-ERR`, `error: invalid reconciliation message`, from a session served
  from a negentropy tree or from memory alike (#219). A NEG-MSG to a session
  served from a tree got that, then a second `NEG-ERR`, `closed: unknown
  subscription handle`; one to a session built in memory got only the
  second, which named the wrong cause. **Clients see new reasons** from a
  session built in memory: a NEG-MSG now gets `error: invalid reconciliation
  message` instead of `closed: unknown subscription handle`, and a NEG-OPEN
  gets it instead of `error: synchronization reconciliation failed`.
- An npub in `admin.pubkeys` makes its key a member under the `members`
  policies while `admin.enabled` is off (#214). Only a file with admin on had
  its `admin.pubkeys` converted to lowercase hex, which membership compares
  them as, so with admin off an npub entry made nobody a member, and a
  reload that rewrote a key from npub to hex logged it as one key added and
  one removed. An entry that is no key still loads while admin is off, but
  the relay now warns about it at startup and on reload, and `wok doctor`
  reports it in a new `admin-pubkeys` check.
- `wok_authenticated_connections` counts connections, as documented, not
  successful AUTHs (#214). A connection that authenticated a second key, or
  the same key again, added one each time but was taken out once when it
  closed, so the gauge drifted upward, and `wok_active_connections -
  wok_authenticated_connections` could go negative.
- A NEG-MSG that crossed the `NEG-ERR` closing its session no longer gets a
  second `NEG-ERR`, `closed: unknown subscription handle` (#214). When a
  reload, a moderation change, a login, an idle timeout or an expiring event
  closed a sync session, a NEG-MSG the client had already sent for it was
  answered as for a handle it never opened, which could hide the reason the
  first `NEG-ERR` gave. A NEG-MSG sent after the relay sent that `NEG-ERR` is
  still answered with `closed: unknown subscription handle`.
- Decoding a zstd-compressed payload no longer zeroes a buffer as large as
  its size bound first. Reindex, search backfill and integrity bound it at
  16 MiB and spent about 75 µs per compressed event zeroing it, more than a
  Schnorr signature check takes; relay reads bound it by
  `events.max_event_size`.
- `wok integrity` derives each event's NIP-50 search postings,
  `wok_Event__tagKind` entries and strfry-layout index entries once, not
  once per posting. A note with N search terms was decompressed and
  tokenized N times, and a follow list with N `p` tags had its tag-kind keys
  and all of its index entries built N times: on a 1M-event social database
  the check had not finished after 25 minutes. Each posting is now checked
  by looking up the event it names, and balanced against the entries the
  event pass found, in 24 MiB of counters whatever the size of the
  database. `Event__replace` postings, from which superseded history is
  counted, are still each checked against their event's replacement key.
  Reports are unchanged, except that a table's unexpected entries are listed
  after its other issues, and those of the strfry-layout indexes after the
  other issues of all ten.
- An `authors` and `kinds` filter past 1,000 (author, kind) pairs under a
  small `limit` no longer reads every event the authors wrote when they
  rarely publish those kinds. A picture feed (`kinds [20,21]`, `limit 50`) of
  1,000 follows took 6.8 s on a 5-million-event database, and 19 s cold; it
  now takes 2.2 ms, and 0.28 s cold. Such a filter now seeks each pair, up
  to 16,384 pairs, whatever its kinds and limit, so its work stays within
  the pairs the query-work ceiling prices. One tag with `kinds` does the
  same on the `(tag, kind, created_at)` index, and now costs its pairs.
  Where most of the authors' events match, the seeks cost more than the old
  plan: a home feed (`kinds [1,6]`) of 1,000 follows takes 3.5 ms instead
  of 2.2 ms.
- NIP-70: a repost (kind 6 or 16) is refused as embedding a protected event
  when its content is an event whose tags include one named `-`, or is a
  JSON object the relay's strict parser refuses. Before, any content
  containing the text `["-"]` was refused, so a repost of an ordinary note
  that merely mentioned it was refused, while a protected event written
  with other spacing, such as `[ "-" ]`, or with a tag like `["-",""]`, got
  through. Content that is not a JSON object is accepted.
- A subscription id may be any non-empty string of up to 64 characters, as
  NIP-01 says. Before, an id containing a control character, `"`, `\` or any
  character outside ASCII was refused, so every non-ASCII id failed, and the
  limit counted bytes, so 64 two-byte characters were too long. EVENT frames
  now JSON-escape the id, as EOSE, CLOSED and COUNT frames already did.
- A REQ or COUNT with no filters is refused with `CLOSED` (`invalid: bad req:
  arr too small`), as NIP-01 requires for a refused REQ, instead of a NOTICE
  that did not say which subscription was refused. A NEG-OPEN with an
  invalid subscription id gets NIP-77 `NEG-ERR` (`invalid:`) instead of a
  NOTICE.
- REQ and COUNT refusals use NIP-01's machine-readable prefixes instead of
  `error:`, which NIP-01 keeps for when none of the others fits. The text
  after the prefix is unchanged:
  - `invalid:` for malformed filters and for requests over a size limit, as
    in `invalid: bad req: arr too big`;
  - `unsupported:` for filter elements NIP-01 does not define, such as an
    unknown key or a tag key that is not a single letter; NEG-OPEN filters
    get it too;
  - `blocked:` for the `relay.filter_validation` rules and for COUNT
    disabled by `relay.max_filter_limit_count = 0`.
  A write-policy plugin's reason that starts with `unsupported:` is now sent
  as is, rather than as `blocked: unsupported: ...`.
- A REQ, COUNT or NEG-OPEN over the query-work ceiling is refused with
  `blocked: query too broad (cost <n> > <max>); split the REQ or narrow
  authors/kinds`, naming the request. Before, it got `rate-limited:`, which
  tells a client to retry a request that will be refused again. NIP-11
  advertises `max_query_work` only while `relay.abuse.enabled` is on and the
  ceiling is not zero; before, it advertised a ceiling that refused nothing.
- An EVENT whose duplicate check could not read the database was refused
  with `invalid:`. It now gets `error:`, because the failure is the relay's.
- A REQ with many filters could hold a req worker well past its time slice
  (`relay.query_timeslice_budget_us`), and every query behind it waited.
  Each filter restarted the slice's clock, and a filter that followed a long
  one did not check the clock until it had done as much work. A REQ's filters
  now share one slice, and each checks the clock from its start. A 30-filter
  REQ that once ran 100 ms without yielding now yields every 10 ms.
- With `relay.compression_sliding_window = false`, the relay reset its
  inflater before every client message although it had not asked the client
  to stop context takeover, so a client compressing against its earlier
  messages, as browsers do, was disconnected on its second compressed
  message. The setting now applies only to the relay's own compressor.
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
- An `authors` and `kinds` filter naming 1000 or more (author, kind) pairs no
  longer reads every event those authors wrote when its kinds are replaceable
  or addressable, as in an outbox fetch of kinds 0, 3 and 10002 for a long
  follow list. The same applies when it names one kind, or when its limit
  covers the extra index seeks, as for COUNT and NEG-OPEN. Such a fetch for 334
  authors took 70 ms or more instead of 2 ms on a 200,000-event database.
- A filter with `until: 0` no longer reads its whole index to return nothing,
  and a filter with `limit: 0` reads no index at all.
- A filter with an empty `ids`, `authors`, `kinds` or `#x` list now matches no
  event, as NIP-01 requires. Before, the whole REQ, COUNT or NEG-OPEN was
  refused with `must not be empty`, so the request lost its other valid filters
  and a client with an empty follow list got an error. The subscription now
  gets EOSE and stays open for its other filters.
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
  other paths return 404, apart from `/admin` and, when they are on,
  `/metrics` and the NodeInfo routes. Before, every path upgraded and served
  NIP-11, so one relay answered under any number of URLs. A reverse proxy
  that serves the relay under a path prefix must now strip the prefix.
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
- A WebSocket text message that is not UTF-8, checked once the message is
  whole and inflated, closes the connection with status 1007, as RFC 6455
  §8.1 requires (#53). Before, the relay read it as the message `x` and
  answered with a NOTICE. A ping, pong, close or continuation frame marked
  compressed (RSV1) closes it with 1002, as RFC 7692 §6 requires; before, a
  compressed ping got a pong. Every frame or message the codec refuses now
  gets a Close frame with its status code before the connection drops: 1002
  for a framing error, 1007 for a compressed message that does not inflate
  and 1009 for one too large. Before, the connection dropped with no Close
  frame, as a read timeout still does.
- A client's WebSocket Close frame is checked before the relay echoes it, as
  RFC 6455 §5.5.1 and §7.4 require. A 1-byte body or a status code that may
  not be sent, such as 1005 or 1016, closes the connection with 1002, and a
  reason that is not UTF-8 with 1007. Before, any body was echoed as sent.
  Each connection failed for breaking the protocol is now logged as `client
  terminated` with the `reason` and `close_code`, as a pong timeout is.
- An `Event` table key that is not 8 bytes long, which only at-rest
  corruption produces, is reported as a database error instead of panicking
  the thread that read it (#56). The scans that walk events in local-id
  order hit it: live subscriptions catching up, `wok monitor`, the router,
  negentropy tree builds, and `wok migrate strfry`'s verification and
  fingerprints.
- `wok compact <file>` writes the compact copy to that file, as `wok compact
  -` writes it to standard output. It failed with `No such file or
  directory`: LMDB took the path for a directory to write `data.mdb` in, and
  the command refuses a path that exists.

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
