# Configuration

Wok uses strict TOML configuration. Start from [wok.toml](wok.toml), a short
annotated file showing the settings a relay must or commonly should set, or
from the file produced by `wok migrate strfry`. Omitted settings inherit the
selected [preset](#preset), whose values are the defaults below; unknown keys,
unknown preset names, wrong types, invalid admin URLs, invalid log filters,
and out-of-range history settings are rejected. This page documents every
setting; `wok config show --defaults` lists each with the preset's value.

The legacy HOCON-subset reader is used only for explicit strfry migration.
It accepts named objects, arrays, and anonymous object blocks inside arrays
(for example `plugins.accept = [ { cmd = "..." } ]`). Those plugin-array
entries are reported as ignored keys; Wok translates only
`relay.writePolicy.plugin` into `relay.write_policy_plugin`. Normal startup,
validation, dashboard writes, and file watching use TOML.

## Reload and dashboard boundaries

`Live` settings are picked up by the configuration watcher and by dashboard
writes. `Restart` settings are parsed on reload but the running process keeps
the startup value. Limits marked `Live (new connections)` affect connections
created after reload. Dashboard editing additionally requires
`admin.allow_config_writes = true` and a relay started from an existing TOML
file.

The dashboard exposes nearly all safe live operator settings: relay metadata,
event acceptance, query/protocol limits, abuse controls, filter validation,
NIP-62, and local history. Database/listener/thread/socket settings are omitted
because they require restart. Admin credentials, proxy trust, authentication
policy, external plugin paths, and diagnostic logging switches remain
file-only to avoid remote self-lockout or security-boundary changes.

## Preset

| Key | Default | Reload | Dashboard | Meaning |
|---|---:|---|---|---|
| `preset` | `public` | Live | No | Named set of defaults this file overlays. |

Settings resolve in three layers: the built-in defaults, then the preset's
overlay, then this file. Each layer replaces individual keys, not whole
sections. A preset ships in the binary as a small TOML overlay containing only
the keys it changes; [presets/](presets/) has a copy of each.

| Preset | Use |
|---|---|
| `public` | A general public relay. Its values are the built-in defaults, so its overlay is empty. |

Further presets, starting with `marmot`, are planned; see
[#97](https://github.com/erskingardner/wok/issues/97).

`wok config show` prints the effective configuration, one dotted key per line,
with the origin of each value: `default`, `preset <name>`, or the file and
line that set it. When the file sets a value other than the preset's, the
preset's value follows in parentheses. `wok config show --overrides` prints
only those keys. The output is itself valid TOML.

```text
preset = "public"                                      # wok.toml:1
relay.abuse.event_burst = 500                          # wok.toml:11 (preset public: 100)
relay.auth.service_url = "wss://relay.example.com"     # wok.toml:8 (preset public: "")
relay.bind = "127.0.0.1"                               # default
```

`wok config show --defaults` prints every setting with the value the file's
preset gives it, ignoring the rest of the file.

Changing `preset` on reload is allowed. The reload log names the preset change,
and every resulting security-scope change is warn-logged like any other
reload. Restart settings keep their startup values. Dashboard saves keep the
file's `preset`.

### Set only overrides

A setting in the file pins its value, even when it equals today's default.
When a release improves a default, a relay whose file repeats the old value
keeps it. Set only what the relay needs and leave the rest to the preset.

- **Dashboard and NIP-86 saves** edit the file in place. They change only the
  settings whose value changed, add a new setting to the end of its table,
  and remove a setting set back to its preset value. Comments, layout and
  `preset` are kept; removing a setting also removes the comment lines
  directly above it.
- **`wok config minimize`** removes every setting that repeats its preset's
  value, so the relay resolves to the same configuration afterwards. It keeps
  the original beside the file as `<file>.bak`, or `.bak.1` and so on if that
  exists. `--dry-run` prints the change as a unified diff and writes nothing.
- **`wok doctor`** warns, in its `config-defaults` check, about settings
  pinned to a default that an earlier release used and the preset has since
  replaced, such as `events.reject_older_than_secs = 94608000`, the default
  through 0.7.0. The relay keeps the old value. Delete the line to use the
  preset's value, or keep it if you chose that value; `minimize` leaves such
  settings alone because removing them changes behavior. The check also
  counts the settings that `minimize` would remove.
- **Deprecated settings** that a release replaced still load, as their
  translation, so the relay behaves as before. Each is warned about at
  startup and on reload, and in `wok doctor`'s `config-deprecations` check.
  `wok config minimize` and dashboard saves rewrite them as their
  translation. The [filter validation](#filter-validation) switch is one.
  The other, `relay.abuse.max_query_cost`, is ignored instead: its values
  mean something else in the units of
  [`max_query_work`](#query-work), which replaced it.

## Admin

| Key | Default | Reload | Dashboard | Meaning |
|---|---:|---|---|---|
| `admin.enabled` | `false` | Live | No | Serve the signed-out shell at `/admin`; APIs still require NIP-98. |
| `admin.public_url` | empty | Live | No | Exact public HTTP(S) origin used to verify the NIP-98 `u` tag. |
| `admin.pubkeys` | `[]` | Live | No | Allowed administrator npubs or lowercase hex public keys. |
| `admin.auth_window_secs` | `60` | Live | No | Accepted NIP-98 freshness window, from 1 through 300 seconds. |
| `admin.allow_config_writes` | `false` | Live | No | Permit typed, validated, atomic dashboard writes. |

The public URL must have no credentials, path, query, or fragment. Each API
request needs a new kind-27235 event with empty content, exactly one matching
`u` and `method` tag, and—when a body is present—a SHA-256 `payload` tag.
Authorization events are single-use. The browser delegates signing to NIP-07;
Wok never receives private key material.

## Database

| Key | Default | Reload | Meaning |
|---|---:|---|---|
| `database.path` | `./wok-db/` | Restart | Wok-owned LMDB directory. |
| `database.max_readers` | `256` | Restart | LMDB reader-slot ceiling. |
| `database.map_size` | `68719476736` | Restart | Maximum LMDB map size in bytes; writes fail atomically at the ceiling. |
| `database.no_read_ahead` | `false` | Restart | Disable LMDB read-ahead for workloads where it is counterproductive. |
| `database.min_free_disk_bytes` | `1073741824` | Restart | Reject durable event batches before free filesystem space falls below this reserve; zero disables the guard. |

## Event acceptance

All event settings reload live and are available in the dashboard.

| Key | Default | Meaning |
|---|---:|---|
| `events.max_event_size` | `1048576` | Maximum normalized serialized event size in bytes. |
| `events.reject_newer_than_secs` | `900` | Maximum accepted future clock skew. |
| `events.reject_older_than_secs` | `0` | Maximum age for regular events; `0` means no lower bound. |
| `events.reject_ephemeral_older_than_secs` | `60` | Maximum age for ephemeral events at publication. |
| `events.ephemeral_lifetime_secs` | `300` | Retention window when ephemeral persistence is `ttl`. |
| `events.ephemeral_persistence` | `live_only` | `live_only` broadcasts without storage; `ttl` persists then expires. |
| `events.max_num_tags` | `5000` | Maximum tags on one event; NIP-11 `max_event_tags`. See [Tags per event](#tags-per-event). |
| `events.max_tag_val_size` | `1024` | Maximum bytes in one tag value. |

Single-letter tag values longer than 255 bytes are indexed by their SHA-256,
so up to `max_tag_val_size` a `#x` filter matches them, an addressable event
whose first `d` tag is that long keeps its own address, and a kind 5 `a` tag
that long deletes its target. An addressable event is refused with `invalid:`
when the `a` tag naming it (`kind:pubkey:d`) would exceed `max_tag_val_size`,
so its first `d` is at most `max_tag_val_size` minus 71 bytes and every stored
address can be referenced and deleted. Records stored by earlier Wok releases
or migrated from strfry lack long values in their indexes until `wok reindex`
restores them; see
[lmdb-v3.md](lmdb-v3.md#packedevent).

The 1 MiB event ceiling accommodates bounded extended-length NIP-44 payloads,
including kind 1059 gift wraps and kind 445 MLS group events. Wok does not
decrypt or identify NIP-44 content, so this remains a global event limit and is
measured after Base64 encoding, JSON escaping, and event metadata are present.
The NIP-44 theoretical maximum is not a relay allocation target. Existing
operator files that explicitly retain `65536` continue enforcing 64 KiB.

### Tags per event

`max_num_tags` is 5,000 in the public preset, and NIP-11 advertises it as
`max_event_tags`.

- **If too low:** heavy users can't save their follow lists (kind 3) or
  mute and other lists (kinds 10000 and 30000). At 2,000, the default
  through 0.7, a follow list of more than 2,000 accounts was refused.
- **If too high:** every single-letter tag is an index entry, so one event
  adds thousands of index writes, and replacing a list removes as many.
  Parsing, verification, the writer's index work and disk use all grow with
  the tag count. The EVENT budgets bound how often one address or author can
  pay that.

### Timestamp windows

`reject_older_than_secs` is off (`0`) in the public preset, and NIP-11 then
omits `created_at_lower_limit`.

- **If too low:** old regular events are refused, so a history import or a
  rebroadcast of old notes fails.
- **If too high:** nothing meaningful. Old events sort below new ones, and
  rates and quotas already bound storage.

A bound that an operator sets applies to regular kinds only. Replaceable
(0, 3, 10000–19999) and addressable (30000–39999) events, deletions (5) and
vanish requests (62) are exempt from it.

Two kinds follow their NIPs instead of the `[events]` windows:

- **AUTH (22242)** is accepted within 600 seconds of the relay clock, in
  either direction, as NIP-42 suggests. The per-connection challenge already
  prevents replay.
- **Ephemeral gift wraps (21059)** may be dated up to three days in the
  past, because NIP-59 backdates wraps by up to two days. This allowance is
  fixed; `reject_ephemeral_older_than_secs` does not change it. Future dates
  are still bounded by `reject_newer_than_secs`. In `ttl` mode a wrap older than
  `ephemeral_lifetime_secs` reaches live subscribers, but the next purge
  removes it, so history does not serve it.

`reject_ephemeral_older_than_secs` still bounds every other ephemeral kind,
such as NIP-46 requests, against replays reaching live subscribers. An event
outside its window is refused with `invalid:`.

## Observability

| Key | Default | Reload | Dashboard | Meaning |
|---|---:|---|---|---|
| `observability.log_format` | `pretty` | Restart | Human-readable `pretty` or newline-delimited `json`. |
| `observability.log_filter` | `wok=info` | Restart | tracing filter; `RUST_LOG` overrides it at startup. |
| `observability.history_enabled` | `true` | Live | Yes | Collect bounded in-memory dashboard samples. Disabling clears them. |
| `observability.history_interval_secs` | `15` | Live | Yes | Seconds between samples; must be at least 1. |
| `observability.history_max_points` | `5760` | Live | Yes | FIFO sample bound, from 0 through 100,000. |

See [Observability](observability.md) for every exported metric and label.

Note: the Prometheus endpoint `/metrics` is served on the same public
listener as client traffic, with `Access-Control-Allow-Origin: *` — any web
page can read connection, event, auth, and abuse-rejection counters
cross-origin. If the relay is internet-facing, scrape it over a private
interface or protect the path at the reverse proxy.

## Relay listener and protocol

| Key | Default | Reload | Dashboard | Meaning |
|---|---:|---|---|---|
| `relay.bind` | `127.0.0.1` | Restart | TCP listen address: an IPv4 or IPv6 literal (`::1` or `[::1]`), or a hostname. A hostname listens on every address it resolves to (`localhost` → `127.0.0.1` and `::1`), skipping resolved addresses that are not assigned on this host or whose family it lacks, as long as one binds. |
| `relay.port` | `7777` | Restart | TCP listen port. |
| `relay.nofiles` | `524288` | Restart | Requested process file-descriptor limit. |
| `relay.real_ip_header` | empty | Live | No | Trusted proxy header containing the client IP; leave empty for direct peers. **The header is fully trusted for every per-address budget** (connection, EVENT, REQ, COUNT): if the proxy passes the client-supplied value through instead of overwriting it, any client can rotate fake IPs to defeat rate limits and burn other IPs' budgets. A startup warning is logged whenever this is set. Left empty behind a proxy, every client has the proxy's address and shares its budgets, so a startup warning is also logged when it is empty and the relay listens only on loopback or private addresses. |
| `relay.max_websocket_payload_size` | `2097152` | Restart | Maximum reassembled WebSocket payload bytes. |
| `relay.max_req_filter_size` | `262144` | Live | Yes | Maximum combined compact-JSON bytes across all filters in one REQ or COUNT. See [Filter size](#filter-size). |
| `relay.max_filter_bytes_per_connection` | `2097152` | Live | Yes | Maximum combined compact-JSON filter bytes of the REQ subscriptions open on one connection, and separately of its COUNTs not yet answered; zero is unlimited. See [Filter size](#filter-size). |
| `relay.max_filters_per_req` | `200` | Live | Yes | Unconditional maximum filter objects in one REQ or COUNT. |
| `relay.auto_ping_seconds` | `55` | Restart | WebSocket ping interval; zero disables automatic pings. A ping unanswered for a full interval closes the connection. |
| `relay.enable_tcp_keepalive` | `false` | Restart | Enable TCP keepalive on accepted sockets. |
| `relay.handshake_timeout_secs` | `10` | Live (new connections) | No | Pre-upgrade HTTP header read deadline (slowloris guard); zero disables it. |
| `relay.frame_read_timeout_secs` | `30` | Live (new connections) | No | Maximum idle gap between socket reads while a partial WebSocket frame or unfinished fragmented message is buffered (slow-trickle guard); zero disables it. |
| `relay.query_timeslice_budget_us` | `10000` | Live | Yes | Query CPU budget before cooperative yielding. |
| `relay.max_filter_limit` | `2000` | Live | Yes | Maximum events one REQ filter returns, and the limit of a filter without one; NIP-11 `max_limit` and `default_limit`. See [Result size](#result-size). |
| `relay.max_tags_per_filter` | `8` | Live | Yes | Maximum distinct tag names across `#` and NIP-91 `&` query keys in one filter. See [Result size](#result-size). |
| `relay.max_and_entries` | `16` | Live | Yes | Maximum distinct values across all NIP-91 `&` query keys in one filter; zero disables NIP-91 and removes it from NIP-11. |
| `relay.max_filter_limit_count` | `1000000` | Live | Yes | Maximum COUNT filter limit. |
| `relay.max_total_events_per_req` | `10000` | Live | Yes | Deduplicated historical events across a REQ; zero is unlimited. See [Result size](#result-size). |
| `relay.max_subs_per_connection` | `200` | Live | Yes | Simultaneous subscriptions per connection, counting those still sending history. A REQ over it gets `CLOSED`; reusing an open id is always allowed. |
| `relay.max_live_buffer_bytes` | `262144` | Live (new subscriptions) | No | Live matches held for one subscription while its history is sent, before EOSE. Past it, stored events are re-read from the database after the history, and the oldest ephemeral events are dropped (`wok_live_buffer_dropped_ephemeral_total`). Zero is unlimited. |
| `relay.max_pending_outbound_bytes` | `33554432` | Live (new connections) | Yes | Pending output budget before slow-client disconnect. |
| `relay.write_policy_plugin` | empty | Live | No | External executable for publication decisions; empty disables it. |
| `relay.write_policy_timeout_secs` | `10` | Live | Yes | Maximum wait for the configured write-policy plugin. |
| `relay.compression_enabled` | `true` | Restart | Enable permessage-deflate negotiation. |
| `relay.compression_sliding_window` | `true` | Restart | Reuse compression context between messages. With context takeover, a connection's compressor can reference bytes from previous messages — the precondition structure for CRIME/BREACH-style oracles when secret and attacker-influenced bytes share a compression context. Relay traffic is essentially all public data, so practical impact is nil for most operators; if you serve auth-bearing or otherwise secret traffic over the same client connections, prefer `false`. |
| `relay.dump_in_all` | `false` | Live | No | Diagnostic logging for every inbound client message. |
| `relay.dump_in_events` | `false` | Live | No | Diagnostic logging for inbound EVENT messages. |
| `relay.dump_in_reqs` | `false` | Live | No | Diagnostic logging for inbound REQ messages. |
| `relay.db_scan_perf` | `false` | Live | No | Emit database scan performance diagnostics. |
| `relay.invalid_events` | `true` | Live | No | Log invalid-event diagnostics. |
| `relay.ingester_threads` | `3` | Restart | Event-ingestion worker count. |
| `relay.req_worker_threads` | `3` | Restart | Historical query worker count. |
| `relay.req_monitor_threads` | `3` | Restart | Query monitor worker count. |
| `relay.negentropy_threads` | `2` | Restart | Negentropy worker count. |
| `relay.negentropy_enabled` | `true` | Live | Yes | Enable and advertise NIP-77 synchronization. |
| `relay.max_sync_events` | `1000000` | Live | Yes | Event ceiling for one temporary Negentropy view; direct trees do not materialize the set. |
| `relay.sync_memory_per_connection` | `268435456` | Live | Yes | Bytes reserved for sync sessions on one connection (256 MiB); zero rejects new sessions. |
| `relay.sync_memory_total` | `1073741824` | Live | Yes | Shared sync reservation ceiling across workers (1 GiB); zero rejects new sessions. |
| `relay.sync_idle_timeout_secs` | `60` | Live | Yes | Maximum idle wait for the next sync message; active construction has no fixed lifetime. Zero expires sessions immediately. |

### Result size

Three settings bound what one REQ returns or asks the relay to check. NIP-11
advertises all three.

- **Events per filter** (`max_filter_limit`, 2,000; `max_limit` and
  `default_limit`). A filter's `limit` is clamped to it, and a filter without
  a `limit` gets it too.
  - If too low: results are cut, and clients make extra round trips. At 500,
    the default through 0.7, MDK's directory batches (`limit` 1,200) and
    outbox metadata fetches without a `limit` lost events.
  - If too high: more output per request. The outbound queue still bounds
    memory.
- **Events per request** (`max_total_events_per_req`, 10,000).
  - If too low: merged batches of filters are cut. At 2,000, the default
    through 0.7, five filters of 500 lost a fifth of their events.
  - If too high: one request can queue many megabytes for a slow client,
    who is then disconnected (`max_pending_outbound_bytes`).
- **Tag letters per filter** (`max_tags_per_filter`, 8).
  - If too low: comment, community and marketplace queries are refused. At
    3, the default through 0.7, a NIP-22 query on `#E`, `#K`, `#P` and `#k`
    was refused.
  - If too high: small extra checks per candidate event.

A history cut by either limit never gets the NIP-67 `finish` hint, and
usually gets `more` (see [nips.md](nips.md)), so a client can page with
`until` for the rest.

### Filter size

Two settings bound the filters a client sends, both in compact JSON bytes.
`max_req_filter_size` bounds the filters of one REQ or COUNT.
`max_filter_bytes_per_connection` bounds the filters of every REQ
subscription open on one connection, because live filters stay in memory
until they are closed. It bounds the COUNTs a connection is waiting on the
same way, separately, since one can wait for a scan slot (see
`max_concurrent_historical_queries`).

- **Filters per request** (`max_req_filter_size`, 256 KiB).
  - If too low: outbox clients can't fetch a large follow list in one
    request. At 64 KiB, the default through 0.7, a REQ naming about 970
    authors or more was refused.
  - If too high: more memory per subscription. The connection budget caps
    the total.
- **Filters per connection** (`max_filter_bytes_per_connection`, 2 MiB).
  - If too low: clients that keep several subscriptions over a long follow
    list open, such as a home feed and a profile feed, have new ones refused.
  - If too high: one connection can hold more filter memory, up to
    `max_subs_per_connection` times `max_req_filter_size` (50 MiB at the
    defaults) with the budget off.

A REQ that would take the connection over its budget is refused with
`CLOSED` and `blocked: this connection's filters exceed <budget> bytes`.
Closing a subscription frees its bytes. A REQ that reuses an open
subscription ID is charged only for the difference, so after a reload lowers
the budget, a subscription can still be replaced by filters no larger than
its own. A COUNT is charged to the COUNT budget until it is answered.

One filter also stops at 65,535 decoded bytes per value list, whatever these
settings are: at most 2,047 `authors`, `ids`, `#e` or `#p` values. 256 KiB
lets one filter reach that ceiling and leaves room for the other filters in
the same REQ.

## Authentication and private reads

These settings reload live but stay file-only because they define an access
control boundary.

| Key | Default | Meaning |
|---|---:|---|
| `relay.auth.enabled` | `true` | Enable NIP-42 authentication. |
| `relay.auth.service_url` | empty | Public relay URL placed in and checked against AUTH challenges. |
| `relay.auth.restricted_read_kinds` | `[4, 1059, 21059]` | Kinds hidden from unauthenticated historical and live reads. |
| `relay.auth.restrict_read_to_involved_pubkey` | `true` | Restrict authenticated reads to the author or first `p`-tag recipient. |
| `relay.auth.restrict_writes` | `false` | Only NIP-86 allowlisted or role-holding pubkeys (and operator admins) may write. NIP-62 vanish requests are exempt. See [nip86.md](nip86.md). |

While AUTH is usable (`enabled` with a `service_url`), every connection
receives its NIP-42 challenge as soon as it opens.

Private reads fail closed until `service_url` is configured. While AUTH is
unusable, those reads are refused with `restricted:` and no AUTH challenge, so
NIP-42 clients do not attempt an AUTH that cannot succeed; with
`enabled = false` the relay refuses AUTH outright. Clearing
`restricted_read_kinds` restores unrestricted history, but Wok stops
advertising NIP-59, which needs both gift-wrap kinds (1059 and the live-only
ephemeral 21059) restricted.

Keep `restrict_read_to_involved_pubkey` at `true` unless you understand the
interplay: with `false`, the per-event delivery filter is skipped entirely
and the REQ-level auth gate only fires for filter groups where **every**
filter is restricted. A mixed REQ such as `[{"kinds":[1]},{"kinds":[1059]}]`
then returns gift wraps to an unauthenticated client (strfry-compatible
behavior).

## Relay information

All fields reload live and are dashboard-editable. They are returned in NIP-11
and presented on the landing page: banner and icon as media, and identity,
contact, and policy values in the Relay information section.

| Key | Default | Meaning |
|---|---:|---|
| `relay.info.name` | `wok default` | Relay display name. |
| `relay.info.description` | `This is a wok instance.` | Public relay description. |
| `relay.info.pubkey` | empty | Operator public key. |
| `relay.info.self_pk` | empty | Relay public key published as NIP-11 `self`. |
| `relay.info.contact` | empty | Operator contact. |
| `relay.info.icon` | empty | Square icon URL. |
| `relay.info.banner` | empty | Wide banner image URL. |
| `relay.info.privacy` | empty | Privacy-policy URL. |
| `relay.info.terms` | empty | Terms-of-service URL. |

`relay.info.nips` intentionally does not exist. Supported NIPs are derived
from compiled behavior and feature settings so metadata cannot claim
unimplemented behavior.

## NIP-62

| Key | Default | Reload | Dashboard | Meaning |
|---|---:|---|---|---|
| `relay.nip62.enabled` | `true` | Live | Yes | Advertise and process Request to Vanish. |
| `relay.nip62.service_url` | empty | Live | Yes | Target URL; falls back to `relay.auth.service_url`. |
| `relay.nip62.deletion_batch_size` | `1000` | Live | Yes | Records physically removed per restart-safe transaction. |

`ALL_RELAYS` always matches. Valid requests are hidden immediately, deletion
markers remain enforced if the feature is later disabled, and physical removal
continues in bounded batches.

## Filter validation

Optional rules for REQ and COUNT filters. Each applies when it is set and is
off at its zero or empty value, which is the public preset's. A filter that
breaks one is refused with `CLOSED` and `blocked: bad req: filter validation
failed: ...`.

| Key | Default | Reload | Dashboard | Meaning |
|---|---:|---|---|---|
| `relay.filter_validation.max_kinds_per_filter` | `0` | Live | Yes | Maximum kinds listed by one filter; zero is unlimited. MDK's directory batches list six. |
| `relay.filter_validation.allowed_kinds` | empty | Live | Yes | Comma-separated kinds a filter may list; empty permits all. A filter without `kinds` is not checked. |
| `relay.filter_validation.require_author_or_tag` | `false` | Live | Yes | Require each filter to name exactly one author, `#p` or `#e` value. This refuses Marmot's `#h` group filters, `ids` fetches and multi-author outbox and directory batches. |

The filters in one REQ are bounded by `relay.max_filters_per_req` alone.

### Files from 0.7 and earlier

Through 0.7 the section applied its rules only with `enabled = true`, and had
its own filter counts, `max_filters_per_req` and `min_filters_per_req`. Those
three keys are gone. A file that still sets them loads as follows, with a
deprecation warning:

- **`enabled = false`**: every rule in the section is ignored, as before.
  This is what copies of the 0.7 `docs/wok.toml` set.
- **`enabled = true`**: the section's rules still apply, with 0.7's default
  of 3 for a `max_kinds_per_filter` it leaves out.
  - Its `max_filters_per_req`, or 0.7's default of 3, becomes
    `relay.max_filters_per_req` when it is lower. Such a REQ is now refused
    with `invalid: bad req: arr too big`.
  - `min_filters_per_req` is dropped. A REQ needs only one filter.
  - `max_kinds_per_filter = 0` refused every filter that lists kinds. Zero
    now means no limit, so those filters are accepted, with a warning at
    startup and in `wok doctor`. To restrict kinds, set `allowed_kinds`.
- **No `enabled`**: the section is read as a current one, so each rule it
  sets applies. Under 0.7 a section without `enabled` was off.

`wok config minimize`, or a dashboard save, rewrites the section this way.
`wok migrate strfry` translates strfry's `relay.filterValidation` the same
way; strfry's section is off unless `enabled = true`.

## Abuse protection

All abuse settings reload live. All but `ipv6_prefix_len` and the
`per_connection` table are dashboard-editable. See [Rates](#rates) for how
the per-connection and per-address budgets combine.

| Key | Default | Meaning |
|---|---:|---|
| `relay.abuse.enabled` | `true` | Enable this protection layer. |
| `relay.abuse.ipv6_prefix_len` | `64` | Leading bits of an IPv6 address that key its per-address budgets, from 1 to 128. One host is usually given a whole /64, so keying each address (128) lets it take a fresh budget with every address it picks. IPv4 addresses are keyed one by one. See [Addresses](#addresses). |
| `relay.abuse.connection_rate_per_second` | `10` | Refilled connection tokens per network address each second. |
| `relay.abuse.connection_burst` | `50` | Connection token-bucket capacity. |
| `relay.abuse.event_rate_per_second` | `50` | Refilled EVENT and AUTH tokens per network address each second. |
| `relay.abuse.event_burst` | `100` | Per-address EVENT and AUTH bucket capacity. |
| `relay.abuse.pubkey_event_rate_per_second` | `25` | Refilled publication tokens per event author each second. An event whose author is not one of its connection's AUTHed identities is charged to the connection's first identity instead; see [Throwaway keys](#throwaway-keys). |
| `relay.abuse.pubkey_event_burst` | `50` | Per-author publication bucket capacity. |
| `relay.abuse.req_rate_per_second` | `200` | Backstop: refilled REQ, NEG-OPEN, and NEG-MSG tokens per network address each second, shared by all of its connections. |
| `relay.abuse.req_burst` | `1000` | Per-address REQ, NEG-OPEN, and NEG-MSG bucket capacity. |
| `relay.abuse.count_rate_per_second` | `20` | Backstop: refilled COUNT tokens per network address each second, shared by all of its connections. |
| `relay.abuse.count_burst` | `50` | Per-address COUNT bucket capacity. |
| `relay.abuse.invalid_rate_per_second` | `5` | Refilled tokens per network address each second for malformed messages, including CLOSE and NEG-CLOSE with an invalid subscription id. Once spent, the client gets one `rate-limited` NOTICE and further malformed messages are ignored until the bucket refills. Valid CLOSE and NEG-CLOSE are never budgeted. |
| `relay.abuse.invalid_burst` | `20` | Per-address malformed-message bucket capacity. |
| `relay.abuse.max_concurrent_historical_queries` | `8` | Historical scans one connection runs at once, counted separately for its REQs and COUNTs (on the req worker) and its NEG-OPENs (on the negentropy worker). A scan over it waits, in arrival order, for one of the same kind to end. At most `relay.max_subs_per_connection` wait; past that a REQ or COUNT is refused with `CLOSED rate-limited: too many historical queries waiting on this connection`. Zero rejects new scans. |
| `relay.abuse.max_query_work` | `20000` | Most index entries a REQ, COUNT or NEG-OPEN may touch, estimated before the scan; zero is unlimited. See [Query work](#query-work). |
| `relay.abuse.max_stored_events` | `0` | Global durable event ceiling; the entire write transaction aborts before exceeding it. Zero, the public preset's value, is unlimited. See [Storage](#storage). |
| `relay.abuse.max_stored_events_per_pubkey` | `1000000` | Hard author storage quota; zero is unlimited. See [Storage](#storage). |
| `relay.abuse.min_pow_difficulty` | `0` | Required NIP-13 leading-zero bits; zero disables it. |
| `relay.abuse.per_connection.req_rate_per_second` | `20` | Refilled REQ tokens per connection each second. REQs that replace a subscription and NEG-OPENs draw on it too. |
| `relay.abuse.per_connection.req_burst` | `100` | Per-connection REQ bucket capacity. A client's startup burst of about 60 REQs fits. |
| `relay.abuse.per_connection.neg_msg_rate_per_second` | `50` | Refilled NEG-MSG tokens per connection each second, for the rounds of sync sessions already admitted by their NEG-OPEN. |
| `relay.abuse.per_connection.neg_msg_burst` | `200` | Per-connection NEG-MSG bucket capacity. |
| `relay.abuse.per_connection.count_rate_per_second` | `5` | Refilled COUNT tokens per connection each second. |
| `relay.abuse.per_connection.count_burst` | `20` | Per-connection COUNT bucket capacity. |
| `relay.abuse.per_connection.authenticated_multiplier` | `4` | An AUTHed connection's per-connection rates and bursts are this many times larger; at least 1. The per-address backstops are not multiplied. |

A zero rate or burst disables that individual token bucket. Unix-socket
connections carry no network address (an empty IP), so by design they bypass
every rate bucket — connection, EVENT, REQ, COUNT, and the per-connection
budgets. Per-author
publication, storage quotas, query-cost gates, and proof-of-work policies
still apply to them. Keep the socket on a trusted host with tight
`mode`/`auth_uids`/`auth_gids`.

### Rates

A REQ, COUNT, NEG-OPEN or NEG-MSG is charged to two budgets, and refused
when either is spent:

- its connection's own (`per_connection.*`): 20 REQs a second with a burst
  of 100, 50 NEG-MSG rounds a second with a burst of 200, and 5 COUNTs a
  second with a burst of 20;
- its address's backstop (`req_*`, `count_*`), which every connection from
  that address shares: 200 REQs a second with a burst of 1,000, and 20
  COUNTs a second with a burst of 50. NEG-MSG rounds draw on the REQ
  backstop.

The connection is charged only when the backstop admits too, so a client
over its own budget does not spend what its address's other connections
have left. Users behind one NAT, office or VPN therefore no longer share a
single 20-REQ budget, and one host still cannot multiply its share without
bound by opening connections.

A REQ that replaces a subscription and a NEG-OPEN start scans, so they draw
on the REQ budgets. NEG-MSG rounds continue a session its NEG-OPEN paid
for, so they have a per-connection budget of their own: a client that runs
a NIP-77 pass per group at startup does not spend the REQs it opens next.

Once a connection has authenticated with NIP-42, its per-connection rates
and bursts are `authenticated_multiplier` (4) times larger, and the larger
burst applies at once. Any key can authenticate on an open relay, so the
backstop is not multiplied. Before 0.8, an AUTHed connection was also
charged to a per-pubkey REQ and COUNT bucket, which made its budget
stricter; those buckets are gone.

Refusals keep `rate-limited:`, because the buckets refill: `CLOSED
rate-limited: REQ budget exhausted` (or `COUNT`, or a NEG-ERR naming
`NEG-OPEN` or `NEG-MSG`) for the connection's own budget, and the same
reason ending `for this address` for the backstop.

Copies of the 0.7 `docs/wok.toml` pin `req_rate_per_second = 20`,
`req_burst = 40`, `count_rate_per_second = 5` and `count_burst = 10`. These
keys keep their meaning, a per-address budget, so such a file keeps the old
per-address limits under the new per-connection ones, and `wok doctor`
lists them.

### Throwaway keys

Marmot signs each group message (kind 445) with a fresh key, and a gift
wrap (1059) is signed by a random one, so a budget keyed on the author would
be full for every event. When a connection has authenticated and publishes
an event whose author is not one of its identities, the per-author EVENT
budget (`pubkey_event_*`) of the connection's first identity is charged
instead, and a refusal reads `rate-limited: EVENT budget exhausted for the
authenticated pubkey`. Events the identity signs itself draw on the same
budget, from any connection.

An unauthenticated connection's events are charged to their authors, so
throwaway keys are bounded there only by the per-address EVENT budget.
MDK publishes 445s anonymously until a relay asks it to authenticate, which
keeps group membership unlinkable at the relay.

Storage is not charged this way: `max_stored_events_per_pubkey` counts
stored events by their author, so throwaway-key events count against no
per-author quota. Per-group (`#h`) and per-recipient quotas are a planned
follow-up ([#97](https://github.com/erskingardner/wok/issues/97) step 9).

### Addresses

A per-address budget is keyed by the client's IPv4 address, or by the
`ipv6_prefix_len` leading bits of its IPv6 address: by default every address
in one /64 shares a budget, as addresses on one host or home network
usually do. An IPv4-mapped IPv6 peer (`::ffff:192.0.2.1`) is its IPv4
address. NIP-86 IP bans and the write-policy plugin's `sourceInfo` still
see the exact address.

Behind a reverse proxy the client's address is the proxy's unless
`relay.real_ip_header` names the header the proxy overwrites with it. The
relay warns at startup when that header is set, and when it is empty while
the relay listens only on loopback or private addresses, as behind a proxy.

On reload, the relay logs a warning for each guard the file sets to zero
(unlimited) while its preset does not. A guard that the preset itself turns
off, such as `max_stored_events` in the public preset, is not warned about.

### Query work

Before a REQ, COUNT or NEG-OPEN opens a cursor, the relay estimates how many
index entries it would touch and refuses it if the estimate is over
`max_query_work`. A REQ gets `CLOSED blocked: query too broad (cost <n> >
<max>); split the REQ or narrow authors/kinds`, a COUNT the same naming the
COUNT, and a NEG-OPEN `NEG-ERR` naming the NEG-OPEN. `blocked:` tells the
client that sending the same request again won't help.
`wok_abuse_rejections_total{reason="query_cost"}` counts the refusals. NIP-11
advertises the ceiling as `limitation.max_query_work` while
`relay.abuse.enabled` is on and the ceiling is not zero.

A filter's estimate follows the plan its scan will run. It counts the
cursors the plan opens:

- one per id for `ids`;
- for tags, one per value of the tag the scan seeds from (one for a NIP-91
  `&` tag). Once the `(tag, kind, created_at)` index is complete, one tag
  with `kinds` costs one per (value, kind) pair;
- one per (author, kind) pair for `authors` with `kinds`, whichever index
  the scan reads;
- one per author for `authors` alone, one per kind for `kinds` alone, and
  one for a filter with neither;
- 1,000 for a NIP-50 `search` filter.

A REQ adds the rows it can return: each filter's `limit`, or
`max_filter_limit` when it has none, and no more than its `ids`. The rows of
all its filters count up to `max_total_events_per_req`. Each NIP-91 `&`
value adds the filter's rows again, for the check on every candidate. A
COUNT costs twice its cursors and a NEG-OPEN its cursors, with no rows:
their scans are not bounded by `limit`, but while they run, by
`max_filter_limit_count` and the COUNT budget, and by `max_sync_events` and
the sync memory budgets.

With the public preset's limits:

| Request | Cost |
|---|---:|
| `{"authors":[150 keys],"limit":20}` | 170 |
| `{"kinds":[11 kinds],"limit":50}` | 61 |
| 45 × `{"#e":[id],"kinds":[7]}` | 10,045 |
| `{"authors":[1000 keys],"kinds":[0,3,10002,10050]}` | 6,000 |
| `{"kinds":[445],"#h":[group id]}` | 2,001 |
| `{}` | 2,001 |
| `{"authors":[2000 keys],"kinds":[50 kinds]}` | 102,000, refused |
| `COUNT {"kinds":[3],"#p":[pubkey]}` | 2 |
| `COUNT {"authors":[2000 keys],"kinds":[50 kinds]}` | 200,000, refused |
| `NEG-OPEN {"kinds":[445],"#h":[group id]}` | 1 |

- **Query work ceiling** (`max_query_work`, 20,000). One unit is about
  2–4 µs of warm index work, so the ceiling lets one request run for about
  50–80 ms.
  - If too low: batched and outbox queries are refused. Through 0.7,
    `max_query_cost = 1000` capped an estimate that ignored `limit`, and
    refused 150 authors with `limit` 20, an 11-kind feed and NDK's
    45-filter reaction batches.
  - If too high: one request can hold a query worker for longer.
  - The estimate cannot see how many entries a cursor reads before it finds
    a match. `{"#t":["nostr"],"authors":[key]}` costs 2,001, but reads the
    `nostr` tag's entries until the author's events turn up. Past 16,384
    (author, kind) pairs, `authors` with `kinds` read the authors' history
    until they find those kinds, which takes seconds for kinds they rarely
    publish.

`relay.abuse.max_query_cost`, which copies of the 0.7 `docs/wok.toml` set to
1000, is deprecated and ignored, with a warning at startup, on reload and in
`wok doctor`. Its values would mean something else in these units: 1,000
would refuse every filter without a `limit`, such as `{"kinds":[1]}` (2,001).
`wok config minimize`, or a dashboard save, removes it. To set a ceiling,
set `max_query_work`.

### Storage

The relay's storage is bounded by the resources it uses:
`database.map_size` caps the LMDB map, and `database.min_free_disk_bytes`
refuses writes before the filesystem fills. The event-count settings sit on
top of those.

- **Stored events globally** (`max_stored_events`, off in the public
  preset).
  - If too low: once it is reached, every write on the relay fails. A busy
    public relay stores far more than 10,000,000 events, the default
    through 0.7.
  - When off, `map_size` and `min_free_disk_bytes` bound storage.
- **Stored events per author** (`max_stored_events_per_pubkey`, 1,000,000).
  - If too low: active users and bots can no longer post new events. At
    quota, an author can still replace their own replaceable and addressable
    events and delete their own events. Only a deletion that removes none of
    their events is refused, since it would add an event and free none.
  - If too high: one key can fill the disk.
  - The quota is charged to the event's author, so throwaway keys such as
    Marmot's kind 445 and gift-wrap 1059 authors never reach it, even on
    an AUTHed connection whose identity pays their EVENT budget (see
    [Throwaway keys](#throwaway-keys)).

A write over a quota is refused with `OK false`: `blocked: author storage
quota exceeded`, or `error: global storage quota of <n> events exceeded` for
the whole batch.

## Unix socket

All Unix-socket settings require restart and are file-only.

| Key | Default | Meaning |
|---|---:|---|
| `relay.unix.enabled` | `false` | Listen on the local framed-JSON Unix socket. |
| `relay.unix.path` | `./wok-db/wok.sock` | Socket filesystem path. |
| `relay.unix.mode` | `0o600` | Permission bits, as TOML octal or decimal. |
| `relay.unix.owner` | empty | User applied with `chown` after bind. |
| `relay.unix.group` | empty | Group applied with `chown` after bind. |
| `relay.unix.auth_uids` | `[]` | Allowed peer UIDs; empty accepts any UID. |
| `relay.unix.auth_gids` | `[]` | Allowed peer GIDs; empty accepts any GID. |
| `relay.unix.max_frame_bytes` | `2097152` | Maximum length-prefixed JSON frame. |
| `relay.unix.max_pending_outbound_bytes` | `33554432` | Pending output budget before disconnect. |

See [Unix socket protocol](unix-socket.md) for framing and peer authorization.
